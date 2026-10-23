#!/usr/bin/env bash
# Build a dataset release from processed captures, then write its statistics report.
#
#   1. dataset-unification/build_dataset.py   -> <data_root>/release/<name>/
#   2. dataset-analysis/analyze_dataset.py    -> DATASET_STATISTICS.md (release + info_dir)
#
# Usage: scripts/build_release.sh [build-config.json]   (default: dataset-info/build-config.json)
#
# Environment overrides:
#   PYTHON  interpreter with pandas + pyarrow for the analysis (default: python3)
set -euo pipefail

REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
CONFIG=${1:-$REPO/dataset-info/build-config.json}
PY=${PYTHON:-python3}
[ -f "$CONFIG" ] || { echo "config not found: $CONFIG" >&2; exit 1; }

echo "=== build release ($CONFIG) ==="
"$PY" "$REPO/dataset-unification/build_dataset.py" "$CONFIG"

# Release and info directories as resolved by the build config.
eval "$("$PY" - "$CONFIG" <<'EOF'
import json, os, shlex, sys
path = os.path.abspath(sys.argv[1])
base = os.path.dirname(path)
cfg = json.load(open(path, encoding="utf-8"))
res = lambda p: p if os.path.isabs(p) else os.path.normpath(os.path.join(base, p))
print("RELEASE=" + shlex.quote(os.path.join(res(cfg["data_root"]), "release", cfg["name"])))
print("INFO=" + shlex.quote(res(cfg["info_dir"]) if cfg.get("info_dir") else ""))
EOF
)"

echo
echo "=== analyze release ($RELEASE) ==="
"$PY" "$REPO/dataset-analysis/analyze_dataset.py" "$RELEASE" ${INFO:+--info-dir "$INFO"}
