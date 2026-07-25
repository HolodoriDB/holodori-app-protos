"""
Needs the QOOAPP_TOKEN environment variable.
"""

from __future__ import annotations

import json
import os
import re

import requests

QOOAPP_TOKEN = os.environ.get("QOOAPP_TOKEN")
assert QOOAPP_TOKEN, "environment variable QOOAPP_TOKEN not set"

REGIONS = {  # region -> QooApp app id
    "jp": 153237,
    "global": 156946,
}


class QooApp(requests.Session):
    def __init__(self) -> None:
        super().__init__()
        self.headers.update(
            {
                "X-Version-Code": "80608",
                "X-Device-ABIs": "arm64-v8a,armeabi-v7a,x86,x86_64",
                "X-User-Token": QOOAPP_TOKEN,
            }
        )

    def metadata(self, app_id: int) -> dict:
        r = self.get(f"https://api.qqaoop.com/store/v11/apps/{app_id}", timeout=30)
        r.raise_for_status()
        body = r.json()
        assert body.get("code") == 200, body
        return body["data"]

    def download_url(self, package: str) -> tuple[str, int]:
        """(direct APK url, version code) — the 302 target's filename carries the version code."""
        r = self.get(
            f"https://api.ppaooq.com/v11/apps/{package}/download",
            allow_redirects=False,
            timeout=30,
        )
        url = r.headers.get("location")
        assert url, f"no download url for {package} (HTTP {r.status_code})"
        name = url.rsplit("/", 1)[-1].split("?")[0].removesuffix(".apk")
        return url, int(name.split("-")[-3])


def _version_name(data: dict) -> str:
    m = re.search(r"[?&#]version=([^&]+)", data.get("checkUpdateUrl") or "")
    return m.group(1) if m else ""


def _stored_vc(region: str) -> int | None:
    try:
        with open(os.path.join(region, "appver.json"), encoding="utf-8") as f:
            return int(json.load(f).get("version_code"))
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return None


def update(qoo: QooApp, region: str, app_id: int) -> None:
    try:
        data = qoo.metadata(app_id)
        package = data["packageId"]
        url, vc = qoo.download_url(package)
    except Exception as exc:
        print(f"{region}: metadata failed: {exc}")
        return

    version_name = _version_name(data)
    if _stored_vc(region) == vc:
        print(f"{region}: up to date ({version_name}, vc {vc})")
        return

    tmp = os.path.join(region, ".temp")
    os.makedirs(tmp, exist_ok=True)
    apk_path = os.path.join(tmp, "base.apk")
    try:
        with qoo.get(url, stream=True, timeout=180) as r:
            r.raise_for_status()
            with open(apk_path, "wb") as f:
                for chunk in r.iter_content(1 << 20):
                    f.write(chunk)
    except Exception as exc:
        print(f"{region}: APK download failed: {exc}")
        return

    os.makedirs(region, exist_ok=True)
    with open(os.path.join(region, "appver.json"), "w", encoding="utf-8") as f:
        json.dump(
            {"package": package, "version_name": version_name, "version_code": vc},
            f,
            indent=2,
        )
        f.write("\n")
    print(f"{region}: {version_name} (vc {vc}) -> {region}/appver.json + {apk_path}")


def main() -> None:
    qoo = QooApp()
    for region, app_id in REGIONS.items():
        update(qoo, region, app_id)


if __name__ == "__main__":
    main()
