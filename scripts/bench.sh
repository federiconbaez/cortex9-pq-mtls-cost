#!/usr/bin/env bash
# Matriz {X25519, X25519MLKEM768} x {sin resumption, con resumption}, REPS
# rondas intercaladas, N handshakes secuenciales por corrida.
# uso: scripts/bench.sh [NET_LABEL]   (NET_LABEL describe la red: none, rtt10, ...)
# Variables: N (def 5000), WARMUP (def 100), REPS (def 5), OUT (def results/raw)
set -euo pipefail
cd "$(dirname "$0")/.."
NET=${1:-none}; N=${N:-5000}; WARMUP=${WARMUP:-100}; REPS=${REPS:-5}; OUT=${OUT:-results/raw}
mkdir -p "$OUT"
cargo build --release --locked -q
BIN=target/release/pq-mtls-cost
f="$OUT/$NET.jsonl"; : > "$f"
for rep in $(seq 1 "$REPS"); do
  for g in x25519 x25519mlkem768; do
    for res in "" "--resumption"; do
      line=$("$BIN" --group "$g" $res -n "$N" --warmup "$WARMUP" --label "$NET")
      echo "$line" | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); d['rep']=$rep; print(json.dumps(d,sort_keys=True))" >> "$f"
      echo "rep=$rep group=$g ${res:-full} ok" >&2
    done
  done
done
echo "escrito $f ($(wc -l < "$f") corridas)" >&2
