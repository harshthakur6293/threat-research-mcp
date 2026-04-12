"""Demo: ingest local sample_inputs with IngestionManager."""

from __future__ import annotations

import json
import sys
from pathlib import Path

# Allow running without pip install -e (repo root = parent of examples/)
_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(_ROOT / "src"))

from threat_research_mcp.ingestion import IngestionManager, sources_from_dict


def main() -> None:
    samples = _ROOT / "examples" / "sample_inputs"
    sources = sources_from_dict(
        {
            "sources": [
                {
                    "name": "sample_inputs",
                    "type": "local_file",
                    "path": str(samples),
                    "pattern": "*.txt",
                    "source_trust": "low",
                }
            ]
        }
    )
    mgr = IngestionManager(sources)
    docs = mgr.run()
    print(json.dumps([d.model_dump() for d in docs], indent=2))


if __name__ == "__main__":
    main()
