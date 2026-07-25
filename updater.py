"""track hololive dreams app versions per region and dump every protobuf on change

per region
- qooapp store api gives the latest version
- if it differs from <region>/appver.json or <region>/protobufs is missing
  - justapk downloads the exact version (xapk, not merged) into <region>/.temp
  - extract libil2cpp.so (arm64-v8a split) and global-metadata.dat (base) from the xapk
  - decrypt the metadata (xor key embedded in the .so)
  - il2cppdumper produces dump.cs and stringliteral.json
  - dump_protos writes <region>/protobufs
  - write <region>/appver.json

fail-hard, any failure raises so the workflow aborts before committing. downloads and dumper
output live under <region>/.temp (gitignored). runs on windows, needs QOOAPP_TOKEN in the env
"""

from __future__ import annotations

import io
import json
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import requests

import dump_protos
import metadata_decrypt

ROOT = Path(__file__).resolve().parent
DUMPER_ZIP = ROOT / "ill2cppdumper.zip"

REGIONS = {  # region folder to (google play package, qooapp app id)
    "jp": ("game.qualiarts.hololive.dreams.jp", 153237),
    "global": ("game.qualiarts.hololive.dreams.com", 156946),
}

QOOAPP_API = "https://api.qqaoop.com/store/v11/apps/{app_id}"
QOOAPP_HEADERS = {
    "X-Version-Code": "80608",
    "X-Device-ABIs": "arm64-v8a,armeabi-v7a,x86,x86_64",
}


# latest version lookup


def _qooapp_details(app_id: int, package: str) -> dict:
    """fetch the qooapp store entry for app_id and return its apk block"""
    token = os.environ.get("QOOAPP_TOKEN")
    if not token:
        raise RuntimeError("environment variable QOOAPP_TOKEN not set")

    resp = requests.get(
        QOOAPP_API.format(app_id=app_id),
        headers={**QOOAPP_HEADERS, "X-User-Token": token},
        timeout=60,
    )
    resp.raise_for_status()
    body = resp.json()
    if body.get("code") != 200:
        raise RuntimeError(f"qooapp app {app_id} returned {body.get('code')}: {body}")

    data = body["data"]
    if data.get("packageId") != package:  # guard against a wrong app id
        raise RuntimeError(
            f"qooapp app {app_id} is {data.get('packageId')}, expected {package}"
        )
    return data["apk"]


# download and unpack


def _download(package: str, version: str, out_dir: Path) -> Path:
    """download the exact version via justapk (source fallback) and return the archive path"""
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True)
    subprocess.run(
        [
            sys.executable,
            "-m",
            "justapk",
            "download",
            package,
            "-v",
            version,
            "--no-convert",
            "-o",
            str(out_dir),
        ],
        check=True,
    )
    archives = [
        p
        for ext in ("*.xapk", "*.apks", "*.apkm", "*.apk")
        for p in out_dir.glob(ext)
        if p.stat().st_size > 1_000_000
    ]
    if not archives:
        raise RuntimeError(f"justapk produced no archive for {package} {version}")
    return max(archives, key=lambda p: p.stat().st_size)


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


def process(region: str, package: str, app_id: int, work: Path) -> bool:
    region_dir = ROOT / region
    protobufs = region_dir / "protobufs"

    apk = _qooapp_details(app_id, package)
    version = apk.get("versionName")
    version_code = apk.get("versionCode")
    if not version:
        raise RuntimeError(f"{region}: qooapp returned no version for {package}")

    if _stored_version(region_dir) == version and protobufs.is_dir():
        print(f"{region}: up to date ({version})")
        return False

    print(f"{region}: updating to {version} (vc {version_code})")
    tmp = region_dir / ".temp"
    archive = _download(package, version, tmp / "download")
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

    (region_dir / "appver.json").write_text(
        json.dumps(
            {
                "package": package,
                "version_name": version,
                "version_code": version_code,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"{region}: {version} -> {count} protobufs")
    return True


def main() -> None:
    work = ROOT / ".temp"
    work.mkdir(exist_ok=True)
    for region, (package, app_id) in REGIONS.items():
        process(region, package, app_id, work)


if __name__ == "__main__":
    main()
