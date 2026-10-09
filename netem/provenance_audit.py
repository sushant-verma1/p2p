"""Inventory DHT/M17 result artifacts and reject evidence without provenance.

Run from the repository root before relying on a report:

    python netem/provenance_audit.py netem/results/m17a-provenance-audit-pre-fix.json

Only a result JSON that records both the explicit binary path and SHA-256 is
verifiable. Raw terminal transcripts and retained logs are supporting material,
not a replacement for that record.
"""
import json
import sys
from pathlib import Path


ROOT = Path(__file__).parent / "results"


def is_relevant(path: Path) -> bool:
    name = path.name
    return name.startswith(("dht-", "m17a-"))


def audit(path: Path):
    rows = []
    for item in sorted(ROOT.rglob("*")):
        if not item.is_file() or not is_relevant(item) or item == path:
            continue
        row = {"file": item.relative_to(ROOT).as_posix(), "kind": item.suffix.lstrip(".")}
        if item.suffix == ".json":
            try:
                data = json.loads(item.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as error:
                row.update({"binary": None, "sha256": None, "status": "void", "reason": str(error)})
            else:
                binary = data.get("binary")
                # Old files have only args.binary (or neither); neither proves
                # the executable actually launched.
                if isinstance(binary, dict) and binary.get("path") and binary.get("sha256"):
                    row.update({"binary": binary["path"], "sha256": binary["sha256"], "status": "verified"})
                else:
                    row.update({"binary": None, "sha256": None, "status": "void",
                                "reason": "missing recorded binary SHA-256"})
        else:
            row.update({"binary": None, "sha256": None, "status": "void",
                        "reason": "transcript/log has no result-JSON provenance"})
        rows.append(row)
    return {
        "scope": "DHT/M17 result artifacts present when the mandatory --binary change landed",
        "files": rows,
        "counts": {
            "total": len(rows),
            "verified": sum(row["status"] == "verified" for row in rows),
            "void": sum(row["status"] == "void" for row in rows),
        },
    }


if __name__ == "__main__":
    destination = Path(sys.argv[1]) if len(sys.argv) == 2 else ROOT / "provenance-audit.json"
    destination.parent.mkdir(parents=True, exist_ok=True)
    result = audit(destination)
    destination.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result["counts"]))
