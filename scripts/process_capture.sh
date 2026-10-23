#!/usr/bin/env bash
# Process one capture end to end in the standard data layout (see data/README.md):
#
#   data/raw/<capture>/pcap/        packet captures        (input, read-only)
#   data/raw/<capture>/attacklog/   attacklog JSON exports (input, read-only)
#   data/interim/<capture>/         per-pcap fragments, manifest, logs
#   data/processed/<capture>/       parquet/, flows.csv, flows_labeled.csv, reports
#
# Usage: scripts/process_capture.sh <capture_id>
#
# Environment overrides:
#   DATA_ROOT  data root                      (default: <repo>/data)
#   PYTHON     interpreter with requirements  (default: python3)
#   WORKERS    parallel extraction workers    (default: 4)
#   STAGE_DIR  Linux-side pcap staging cache  (default: extract.py's ~/ids-staged)
set -euo pipefail

if [ $# -ne 1 ]; then
    sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'
    exit 2
fi
CAPTURE=$1
REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
DATA=${DATA_ROOT:-$REPO/data}
PY=${PYTHON:-python3}
WORKERS=${WORKERS:-4}

RAW=$DATA/raw/$CAPTURE
INTERIM=$DATA/interim/$CAPTURE
OUT=$DATA/processed/$CAPTURE
[ -d "$RAW/pcap" ] || { echo "missing $RAW/pcap" >&2; exit 1; }
[ -d "$RAW/attacklog" ] || { echo "missing $RAW/attacklog" >&2; exit 1; }
mkdir -p "$INTERIM" "$OUT"

step() { echo; echo "=== [$CAPTURE] $* ==="; }

step "1/5 extract flows per pcap"
"$PY" "$REPO/flow-extraction/extract.py" --input-dir "$RAW/pcap" --capture-id "$CAPTURE" \
    --work-dir "$INTERIM" --workers "$WORKERS" ${STAGE_DIR:+--stage-dir "$STAGE_DIR"}

step "2/5 stitch fragments into flows"
"$PY" "$REPO/flow-extraction/consolidate.py" --work-dir "$INTERIM" --output-dir "$OUT"

step "3/5 validate"
"$PY" "$REPO/flow-extraction/validate.py" --work-dir "$INTERIM" --output-dir "$OUT" | tail -1
echo "report: $OUT/validation_report.json"

step "4/5 export CSV"
"$PY" "$REPO/flow-extraction/export_csv.py" --dataset-dir "$OUT/parquet" --out "$OUT/flows.csv"

step "5/5 label flows"
"$PY" "$REPO/flow-labeling/label_flows.py" --flows "$OUT/flows.csv" --attacklog "$RAW/attacklog" \
    --out "$OUT/flows_labeled.csv" --summary "$OUT/labeling_summary.json"

echo
echo "Capture $CAPTURE done: $OUT"
