from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
import urllib.request
import zipfile
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate community registry packages.")
    parser.add_argument("registry_json", help="Path to sensor-registry.json")
    args = parser.parse_args()

    registry_path = Path(args.registry_json)
    if not registry_path.exists():
        print(f"Registry file not found: {registry_path}")
        return 1

    data = json.loads(registry_path.read_text(encoding="utf-8"))
    packages = data.get("packages", [])
    if not isinstance(packages, list) or not packages:
        print("Registry must include a non-empty 'packages' list.")
        return 1

    failures = 0
    for pkg in packages:
        name = pkg.get("name", "unknown")
        url = pkg.get("url", "")
        sha256 = (pkg.get("sha256") or "").lower()
        if not url:
            print(f"[{name}] missing url")
            failures += 1
            continue
        if not sha256:
            print(f"[{name}] missing sha256")
            failures += 1
            continue

        try:
            payload = download(url)
        except Exception as exc:
            print(f"[{name}] download failed: {exc}")
            failures += 1
            continue

        digest = hashlib.sha256(payload).hexdigest()
        if digest != sha256:
            print(f"[{name}] sha256 mismatch: expected {sha256} got {digest}")
            failures += 1
            continue

        try:
            validate_zip(payload, name)
        except Exception as exc:
            print(f"[{name}] package validation failed: {exc}")
            failures += 1

    if failures:
        print(f"Validation failed for {failures} package(s).")
        return 1

    print("Registry validation passed.")
    return 0


def download(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "autofw-registry-validator/1.0"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read()


def validate_zip(payload: bytes, name: str) -> None:
    with tempfile.TemporaryDirectory() as tmp_dir:
        zip_path = Path(tmp_dir) / f"{name}.zip"
        zip_path.write_bytes(payload)
        with zipfile.ZipFile(zip_path, "r") as zf:
            zf.extractall(Path(tmp_dir) / "pkg")

        pkg_root = find_package_root(Path(tmp_dir) / "pkg")
        if not pkg_root:
            raise ValueError("could not find package root with sensor.yaml or display.yaml")

        validate_structure(pkg_root)


def find_package_root(root: Path) -> Path | None:
    if (root / "sensor.yaml").exists() or (root / "display.yaml").exists():
        return root
    candidates = [d for d in root.iterdir() if d.is_dir()]
    for d in candidates:
        if (d / "sensor.yaml").exists() or (d / "display.yaml").exists():
            return d
    return None


def validate_structure(pkg_root: Path) -> None:
    if not (pkg_root / "components_map.yaml").exists():
        raise ValueError("missing components_map.yaml")
    if not ((pkg_root / "sensor.yaml").exists() or (pkg_root / "display.yaml").exists()):
        raise ValueError("missing sensor.yaml or display.yaml")


if __name__ == "__main__":
    raise SystemExit(main())
