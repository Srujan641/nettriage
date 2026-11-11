#!/usr/bin/env bash
# NetTriage lab runner.
#
#   ./run.sh up            build and start the lab
#   ./run.sh all           run every scenario, saving a report and packet captures
#   ./run.sh 02-tcp-reset  run one scenario
#   ./run.sh shell         open a shell in the client container
#   ./run.sh down          stop the lab and remove its networks
#
# Results land in labs/captures/<scenario>/ : report.json plus .pcap files for Wireshark.
set -euo pipefail
cd "$(dirname "$0")"

RESOLVER=10.77.0.53
FILTER="not arp and not ip6"
dc() { docker compose "$@"; }
field() { python3 -c "import json,sys; v=json.load(open('scenarios/$1/scenario.json')).get('$2',''); print(v if isinstance(v,str) else json.dumps(v))"; }

run_scenario() {
  local id="$1" out="/captures/$1"
  [ -f "scenarios/$id/scenario.json" ] || { echo "unknown scenario: $id" >&2; exit 64; }
  local target ports router
  target="$(field "$id" target)"; ports="$(field "$id" ports)"; router="$(field "$id" router)"
  mkdir -p "captures/$id"
  rm -f "captures/$id"/*.pcap "captures/$id/report.json"

  echo; echo "━━━ $id: $(field "$id" title)"
  if [ -n "$router" ]; then   # second vantage point: capture on a router as well
    dc exec -d "$router" tcpdump -i any -U -n -s 0 -w "$out/$router.pcap" "$FILTER"
    sleep 1
  fi
  # A broken target makes nettriage exit non-zero; that is the expected outcome here.
  dc exec -T client nettriage "$target" --resolver "$RESOLVER" --ports "$ports" \
     --pcap "$out/client.pcap" --capture-filter "$FILTER" -o "$out/report.json" --no-color || true
  if [ -n "$router" ]; then
    sleep 1; dc exec -T "$router" pkill -INT tcpdump || true; sleep 1
  fi

  # Optional contrast runs recorded into their own capture files.
  python3 - "$id" <<'PY' | while IFS=$'\t' read -r xtarget xpcap; do
import json, sys
for e in json.load(open(f"scenarios/{sys.argv[1]}/scenario.json")).get("extra", []):
    print(e["target"], e["pcap"], sep="\t")
PY
    echo; echo "    contrast run: $xtarget"
    dc exec -T client nettriage "$xtarget" --resolver "$RESOLVER" --ports "$ports" \
       --pcap "$out/$xpcap" --capture-filter "$FILTER" --no-color </dev/null | sed -n '/^VERDICT/,/^$/p' || true
  done
  echo "    saved: labs/captures/$id/ ($(ls "captures/$id" | tr '\n' ' '))"
}

case "${1:-}" in
  up)    dc up -d --build --wait ;;
  down)  dc down -v ;;
  shell) dc exec client bash ;;
  all)   dc up -d --wait >/dev/null 2>&1 || dc up -d --build --wait
         for d in scenarios/*/; do run_scenario "$(basename "$d")"; done ;;
  "")    sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//' ;;
  *)     dc up -d --wait >/dev/null 2>&1 || dc up -d --build --wait
         run_scenario "$1" ;;
esac
