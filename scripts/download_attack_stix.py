"""Download the latest MITRE ATT&CK Enterprise STIX bundle.

Usage:
    python scripts/download_attack_stix.py

Downloads enterprise-attack.json (~50 MB) from the official MITRE CTI
repository into playbook/enterprise-attack.json.  Required for STIX-backed
enrichment tools (enrich_techniques_stix, stix_status).

The file is in .gitignore — do not commit it.  Re-run quarterly when
ATT&CK releases a new version (typically April and October).
"""

from __future__ import annotations

import sys
import urllib.request
from pathlib import Path

URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

DEST = Path(__file__).parent.parent / "playbook" / "enterprise-attack.json"


def _progress(block: int, block_size: int, total: int) -> None:
    downloaded = block * block_size
    if total > 0:
        pct = min(100, downloaded * 100 // total)
        mb = downloaded / 1_048_576
        total_mb = total / 1_048_576
        print(f"\r  {pct:3d}%  {mb:.1f} / {total_mb:.1f} MB", end="", flush=True)


def main() -> None:
    DEST.parent.mkdir(parents=True, exist_ok=True)

    if DEST.exists():
        size_mb = DEST.stat().st_size / 1_048_576
        print(f"enterprise-attack.json already exists ({size_mb:.1f} MB).")
        answer = input("Re-download? [y/N] ").strip().lower()
        if answer != "y":
            print("Skipped.")
            return

    print("Downloading ATT&CK STIX bundle from MITRE CTI …")
    print(f"  Source : {URL}")
    print(f"  Dest   : {DEST}")

    try:
        urllib.request.urlretrieve(URL, DEST, reporthook=_progress)
        print()
        size_mb = DEST.stat().st_size / 1_048_576
        print(f"Done — {size_mb:.1f} MB saved to {DEST}")
        print("STIX enrichment is now active.  Re-run quarterly for ATT&CK updates.")
    except Exception as exc:
        print(f"\nDownload failed: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
