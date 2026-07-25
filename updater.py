"""track hololive dreams app versions per region and dump every protobuf on change

per region
- justapk info is probed across every source for the highest advertised version
- if it differs from <region>/appver.json or <region>/protobufs is missing
  - every justapk source is downloaded into <region>/.temp and the archive with the
    highest versionCode wins, since the mirrors disagree and lag by different amounts
  - extract libil2cpp.so (arm64-v8a split) and global-metadata.dat (base) from the xapk
  - decrypt the metadata (xor key embedded in the .so)
  - il2cppdumper produces dump.cs and stringliteral.json
  - dump_protos writes <region>/protobufs
  - write <region>/appver.json

fail-hard, any failure raises so the workflow aborts before committing. downloads and dumper
output live under <region>/.temp (gitignored). runs on windows, no credentials needed
"""

from __future__ import annotations

import io
import json
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

from justapk.downloader import APKDownloader
from justapk.sources import SOURCE_PRIORITY
from pyaxmlparser import APK

import dump_protos
import metadata_decrypt

ROOT = Path(__file__).resolve().parent
DUMPER_ZIP = ROOT / "ill2cppdumper.zip"

REGIONS = {  # region folder to google play package
    "jp": "game.qualiarts.hololive.dreams.jp",
    "global": "game.qualiarts.hololive.dreams.com",
}

# latest version probe


def _probe(package: str) -> tuple[str | None, int]:
    """ask every source what it currently advertises, cheap, no download

    returns the highest version seen as (version_name, version_code). sources that
    report no version code give 0, so the name comparison is what catches those
    """
    dl = APKDownloader()
    best_name, best_code = None, 0
    seen: list[str] = []

    for source in SOURCE_PRIORITY:
        try:
            info = dl.info(package, source=source)
        except Exception:
            continue
        if not info or not info.version:
            continue
        code = int(info.version_code or 0)
        seen.append(f"{source} {info.version} ({code or '?'})")
        if best_name is None or code > best_code:
            best_name, best_code = info.version.lstrip("v"), code

    print(f"  probe: {', '.join(seen) if seen else 'no source answered'}")
    return best_name, best_code


# download and unpack


def _apk_version(archive: Path, tmp: Path) -> tuple[str, int]:
    """read versionName and versionCode out of an apk or xapk

    prefers the xapk manifest.json (cheap), falls back to parsing the binary
    AndroidManifest.xml of the base split
    """
    with zipfile.ZipFile(archive) as z:
        names = z.namelist()

        if "manifest.json" in names:
            man = json.loads(z.read("manifest.json"))
            if man.get("version_code"):
                return str(man.get("version_name", "")), int(man["version_code"])

        inner = [n for n in names if n.endswith(".apk")]
        if inner:  # xapk, parse the biggest split (the base)
            base = max(inner, key=lambda n: z.getinfo(n).file_size)
            scratch = tmp / "_base.apk"
            scratch.write_bytes(z.read(base))
            target = scratch
        else:
            target = archive

    apk = APK(str(target))
    code = apk.version_code
    if code is None:
        raise RuntimeError(f"no versionCode in {archive.name}")
    return apk.version_name, int(code)


def _archives_in(d: Path) -> list[Path]:
    return [
        p
        for ext in ("*.xapk", "*.apks", "*.apkm", "*.apk")
        for p in d.glob(ext)
        if p.stat().st_size > 1_000_000
    ]


def _download(package: str, out_dir: Path) -> tuple[Path, str, int]:
    """try every justapk source, return the archive with the highest versionCode

    the sources disagree and lag by different amounts, and justapk on its own returns
    whichever one answers first, so ask all of them and compare what actually arrived
    """
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True)

    dl = APKDownloader(auto_convert_xapk=False)
    best: tuple[Path, str, int] | None = None
    failures: list[str] = []

    for source in SOURCE_PRIORITY:
        dest = out_dir / source
        dest.mkdir(parents=True, exist_ok=True)
        try:
            dl.download(package=package, output_dir=dest, source=source, version=None)
        except Exception as e:  # a dead source must not sink the run
            failures.append(f"{source}: {type(e).__name__} {e}")
            continue

        archives = _archives_in(dest)
        if not archives:
            failures.append(f"{source}: no archive produced")
            continue
        archive = max(archives, key=lambda p: p.stat().st_size)

        try:
            name, code = _apk_version(archive, out_dir)
        except Exception as e:
            failures.append(f"{source}: unreadable manifest, {e}")
            continue

        print(f"  {source}: {name} ({code})")
        if best is None or code > best[2]:
            best = (archive, name, code)

    if best is None:
        raise RuntimeError(
            f"no source yielded a usable archive for {package}\n  "
            + "\n  ".join(failures)
        )
    return best


def _scan_apk(z: zipfile.ZipFile) -> tuple[bytes | None, bytes | None]:
    so = meta = None
    for name in z.namelist():
        norm = name.replace("\\", "/")
        if norm.endswith("lib/arm64-v8a/libil2cpp.so"):
            so = z.read(name)
        elif norm.endswith("assets/bin/Data/Managed/Metadata/global-metadata.dat"):
            meta = z.read(name)
    return so, meta


def _extract_so_metadata(archive: Path) -> tuple[bytes, bytes]:
    """pull the arm64-v8a libil2cpp.so and global-metadata.dat out of an apk or xapk"""
    z = zipfile.ZipFile(archive)
    inner = [n for n in z.namelist() if n.endswith(".apk")]
    so = meta = None
    if inner:  # xapk, split apks nested inside
        for n in inner:
            s, m = _scan_apk(zipfile.ZipFile(io.BytesIO(z.read(n))))
            so = so or s
            meta = meta or m
    else:  # single merged apk
        so, meta = _scan_apk(z)
    if not so:
        raise RuntimeError(f"arm64-v8a libil2cpp.so not found in {archive.name}")
    if not meta:
        raise RuntimeError(f"global-metadata.dat not found in {archive.name}")
    return so, meta


# il2cppdumper


def _prepare_dumper(work: Path) -> Path:
    dumper = work / "il2cppdumper"
    if not (dumper / "Il2CppDumper.exe").exists():
        with zipfile.ZipFile(DUMPER_ZIP) as z:
            z.extractall(dumper)
        cfg = dumper / "config.json"
        conf = json.loads(cfg.read_text(encoding="utf-8"))
        conf["RequireAnyKey"] = False  # no keypress prompt
        conf["GenerateDummyDll"] = (
            False  # slow and unused, stringliteral.json needs GenerateStruct
        )
        cfg.write_text(json.dumps(conf, indent=2), encoding="utf-8")
    return dumper


def _run_dumper(dumper: Path, so_path: Path, meta_path: Path, out_dir: Path) -> None:
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True)
    proc = subprocess.run(
        [str(dumper / "Il2CppDumper.exe"), str(so_path), str(meta_path), str(out_dir)],
        cwd=str(dumper),
        capture_output=True,
        text=True,
    )
    if (
        not (out_dir / "dump.cs").exists()
        or not (out_dir / "stringliteral.json").exists()
    ):
        raise RuntimeError(
            "il2cppdumper did not produce dump.cs and stringliteral.json\n"
            f"stdout: {proc.stdout[-800:]}\nstderr: {proc.stderr[-400:]}"
        )


# per-region driver


def _stored_version(region_dir: Path) -> str | None:
    try:
        return json.loads((region_dir / "appver.json").read_text(encoding="utf-8")).get(
            "version_name"
        )
    except (OSError, json.JSONDecodeError):
        return None


def _stored_code(region_dir: Path) -> int:
    try:
        return int(
            json.loads((region_dir / "appver.json").read_text(encoding="utf-8")).get(
                "version_code", 0
            )
        )
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        return 0


def process(region: str, package: str, work: Path) -> bool:
    region_dir = ROOT / region
    protobufs = region_dir / "protobufs"

    print(f"{region}: probing sources")
    probe_name, probe_code = _probe(package)
    stored_code = _stored_code(region_dir)
    fresh = probe_name is not None and (
        probe_name == _stored_version(region_dir) and probe_code <= stored_code
    )
    if fresh and protobufs.is_dir():
        print(f"{region}: up to date ({probe_name})")
        return False

    print(f"{region}: downloading, best advertised is {probe_name}")
    tmp = region_dir / ".temp"
    archive, apk_version, apk_version_code = _download(package, tmp / "download")
    if apk_version_code <= stored_code and protobufs.is_dir():
        print(
            f"{region}: best source has {apk_version} ({apk_version_code}), not newer"
        )
        return False
    so_bytes, meta_bytes = _extract_so_metadata(archive)

    so_path = tmp / "libil2cpp.so"
    meta_path = tmp / "global-metadata.dat"
    so_path.write_bytes(so_bytes)
    meta_path.write_bytes(metadata_decrypt.decrypt(meta_bytes, so_bytes))

    dumper = _prepare_dumper(work)
    dump_out = tmp / "il2cpp_dump"
    _run_dumper(dumper, so_path, meta_path, dump_out)

    count = dump_protos.dump(
        so_path, dump_out / "dump.cs", dump_out / "stringliteral.json", protobufs
    )
    octo_key, app_octo_key, octo_db_key = dump_protos.extract_octo_keys(
        dump_out / "dump.cs"
    )

    (region_dir / "appver.json").write_text(
        json.dumps(
            {
                "package": package,
                "version_name": apk_version,
                "version_code": apk_version_code,
                "source": archive.parent.name,
                "android_octo_key": octo_key,
                "android_app_octo_key": app_octo_key,
                "android_octo_db_key": octo_db_key,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"{region}: {apk_version} ({apk_version_code}) -> {count} protobufs")
    return True


def main() -> None:
    work = ROOT / ".temp"
    work.mkdir(exist_ok=True)
    for region, package in REGIONS.items():
        process(region, package, work)


if __name__ == "__main__":
    main()
