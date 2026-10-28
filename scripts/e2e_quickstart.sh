#!/usr/bin/env bash
# Run the README quick start on a fresh install, against the local demo server.
#
# Creates a new virtual environment in a temporary directory, installs this checkout
# into it (the same as `pipx install git+...` does), starts the demo server in its
# broken mode and runs the quick start commands, checking the output the README shows.
#
#   scripts/e2e_quickstart.sh            # uses python3
#   PYTHON=python3.12 scripts/e2e_quickstart.sh
set -euo pipefail

PYTHON="${PYTHON:-python3}"
PORT="${PORT:-8766}"
repo="$(cd "$(dirname "$0")/.." && pwd)"
work="$(mktemp -d)"
server_pid=""
cleanup() {
  if [ -n "$server_pid" ]; then kill "$server_pid" 2>/dev/null || true; fi
  rm -rf "$work"
}
trap cleanup EXIT

"$PYTHON" -m venv "$work/venv"
"$work/venv/bin/python" -m pip install --quiet --disable-pip-version-check "$repo"
cd "$work"
bin="$work/venv/bin/mcp-auth-doctor"
"$bin" --version

"$work/venv/bin/python" "$repo/scripts/demo_server.py" --port "$PORT" --broken &
server_pid=$!
for _ in $(seq 1 50); do
  if "$work/venv/bin/python" -c "import socket; socket.create_connection(('127.0.0.1', $PORT), 0.2)" 2>/dev/null; then
    break
  fi
  sleep 0.1
done
if ! kill -0 "$server_pid" 2>/dev/null; then
  echo "FAIL: the demo server did not start (is port $PORT in use? set PORT=...)" >&2
  exit 1
fi
url="http://127.0.0.1:$PORT/mcp"

expect() { # expect <file> <text>
  if ! grep -qF -- "$2" "$1"; then
    echo "FAIL: expected to find: $2" >&2
    cat "$1" >&2
    exit 1
  fi
}
run() { # run <expected exit code> <output file> <args...>
  local want="$1" out="$2"
  shift 2
  set +e
  "$bin" "$@" >"$out"
  local got=$?
  set -e
  if [ "$got" != "$want" ]; then
    echo "FAIL: mcp-auth-doctor $* exited $got, expected $want" >&2
    cat "$out" >&2
    exit 1
  fi
}

# Quick start, line 2: the table.
run 1 table.txt "$url"
expect table.txt "prm-resource               FAIL  resource differs from the MCP URL only by a trailing slash (resource has the slash)"
expect table.txt 'as-pkce                    FAIL  `code_challenge_methods_supported` is absent'
expect table.txt "11 pass, 3 fail, 1 warn, 3 skip. Verdict: FAIL (exit 1)"

# -v adds evidence for every check.
run 1 verbose.txt "$url" -v
if [ "$(wc -l <verbose.txt)" -le "$(wc -l <table.txt)" ]; then
  echo "FAIL: -v added no evidence" >&2
  exit 1
fi

# Quick start, line 3: JSON.
run 1 report.json "$url" --json
"$work/venv/bin/python" - <<'PY'
import json

d = json.load(open("report.json"))
assert d["summary"]["exit_code"] == 1, d["summary"]
assert any(c["id"] == "prm-resource" and c["status"] == "fail" for c in d["checks"])
PY

# Extra headers for a gateway.
run 1 headers.txt "$url" -H 'X-Tenant: demo' -H 'X-Trace: abc'
expect headers.txt "Verdict: FAIL (exit 1)"

# Record a run, stop the server, replay it offline.
run 1 recorded.txt "$url" --record run.json
kill "$server_pid"
wait "$server_pid" 2>/dev/null || true
server_pid=""
run 1 replayed.txt --replay run.json
# The replay header names its source; everything after it must match the live run.
expect replayed.txt "(replayed from run.json)"
diff <(tail -n +2 recorded.txt) <(tail -n +2 replayed.txt)

echo "quick start OK on a fresh install"
