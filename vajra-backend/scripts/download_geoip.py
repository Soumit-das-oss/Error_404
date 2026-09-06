"""
VAJRA Forensic Platform - GeoLite2 Binary Downloader
Downloads compiled MaxMind GeoLite2-City and GeoLite2-ASN databases
into vajra-backend/data/ if missing or incomplete (< 1 KB).
"""

import sys
import os
import time
from pathlib import Path
import urllib.request
import urllib.error

# Determine paths
SCRIPT_DIR = Path(__file__).resolve().parent
BASE_DIR = SCRIPT_DIR.parent
DATA_DIR = BASE_DIR / "data"

DATABASES = [
    {
        "name": "GeoLite2-City.mmdb",
        "url": "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb",
    },
    {
        "name": "GeoLite2-ASN.mmdb",
        "url": "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-ASN.mmdb",
    },
]


def download_database(db_info: dict) -> bool:
    name = db_info["name"]
    url = db_info["url"]
    target_path = DATA_DIR / name

    # Check if already present and valid
    if target_path.exists():
        file_size = target_path.stat().st_size
        if file_size >= 1024:
            size_mb = file_size / (1024 * 1024)
            print(f"[+] Found {name} ({size_mb:.2f} MB). Skipping download.")
            return True
        else:
            print(f"[!] {name} exists but is incomplete ({file_size} bytes). Re-downloading...")
            target_path.unlink()

    print(f"[*] Fetching {name} from {url}...")
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) VAJRA-Forensics/1.0"}
    req = urllib.request.Request(url, headers=headers)

    tmp_path = DATA_DIR / f"{name}.tmp"
    try:
        with urllib.request.urlopen(req, timeout=60) as response, open(tmp_path, "wb") as out_file:
            total_length = response.headers.get("Content-Length")
            total_size = int(total_length) if total_length else 0
            block_size = 65536
            downloaded = 0

            while True:
                chunk = response.read(block_size)
                if not chunk:
                    break
                out_file.write(chunk)
                downloaded += len(chunk)
                if total_size > 0:
                    percent = min(100.0, (downloaded / total_size) * 100)
                    sys.stdout.write(f"\r    -> Progress: {downloaded / (1024*1024):.1f} MB / {total_size / (1024*1024):.1f} MB ({percent:.1f}%)")
                    sys.stdout.flush()

        print()
        if tmp_path.exists() and tmp_path.stat().st_size >= 1024:
            if target_path.exists():
                target_path.unlink()
            tmp_path.rename(target_path)
            size_mb = target_path.stat().st_size / (1024 * 1024)
            print(f"[+] Successfully installed {name} ({size_mb:.2f} MB)")
            return True
        else:
            print(f"[-] Downloaded file {name} was too small or corrupted.")
            if tmp_path.exists():
                tmp_path.unlink()
            return False

    except Exception as e:
        print(f"\n[-] Error downloading {name}: {e}")
        if tmp_path.exists():
            tmp_path.unlink()
        return False


def main():
    print("=" * 60)
    print("   VAJRA Forensic Platform - MaxMind GeoIP Binary Installer   ")
    print("=" * 60)

    DATA_DIR.mkdir(parents=True, exist_ok=True)

    success = True
    for db in DATABASES:
        ok = download_database(db)
        if not ok:
            success = False

    print("=" * 60)
    if success:
        print("[+] All GeoIP binary databases are verified and ready for forensic analysis.")
        sys.exit(0)
    else:
        print("[!] Some databases failed to download. Mock GeoIP fallback will be active.")
        sys.exit(1)


if __name__ == "__main__":
    main()
