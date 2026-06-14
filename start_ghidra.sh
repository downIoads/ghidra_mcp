#!/usr/bin/env bash
# Start a Ghidra GUI instance with the GhidraMCP plugin so the embedded HTTP
# server (which bridge_mcp_ghidra.py talks to) comes up. Safe to run when a
# server is already listening — it detects that and exits without launching a
# second instance.
#
# Why this exists: the MCP bridge is a long-lived stdio process and stays up
# even when Ghidra isn't, so every mcp__ghidra__* tool fails with
# "Connection refused". This script (and the start_ghidra_server MCP tool that
# calls it) is the supported way to bring the backend up without leaving the
# session.
#
# Usage:
#   ./start_ghidra.sh                 # restore last project + tools, wait for server
#   ./start_ghidra.sh /path/proj.gpr  # open a specific project, wait for server
#   ./start_ghidra.sh --status        # just report whether the server is up
#
# Environment overrides:
#   GHIDRA_INSTALL_DIR   Ghidra install root (contains ./ghidraRun)
#   GHIDRA_SERVER_URL    server base URL          (default http://127.0.0.1:8080/)
#   GHIDRA_START_TIMEOUT seconds to wait for /ready (default 120)
set -euo pipefail

SERVER_URL="${GHIDRA_SERVER_URL:-http://127.0.0.1:8080/}"
SERVER_URL="${SERVER_URL%/}"
TIMEOUT="${GHIDRA_START_TIMEOUT:-120}"
PROJECT_ARG=""
STATUS_ONLY=0

msg()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!! \033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31mxx \033[0m %s\n' "$*" >&2; exit 1; }

for arg in "$@"; do
    case "$arg" in
        --status) STATUS_ONLY=1 ;;
        -h|--help) sed -n '2,30p' "$0"; exit 0 ;;
        *) PROJECT_ARG="$arg" ;;
    esac
done

server_up() {
    curl -fsS -m 3 "${SERVER_URL}/ready" >/dev/null 2>&1
}

if server_up; then
    msg "Ghidra MCP server already listening at ${SERVER_URL}/"
    exit 0
fi

if (( STATUS_ONLY )); then
    warn "No Ghidra MCP server at ${SERVER_URL}/ (backend not running)."
    exit 1
fi

# Resolve the Ghidra install dir.
find_ghidra() {
    if [[ -n "${GHIDRA_INSTALL_DIR:-}" && -x "${GHIDRA_INSTALL_DIR}/ghidraRun" ]]; then
        printf '%s\n' "$GHIDRA_INSTALL_DIR"; return 0
    fi
    local candidates=()
    candidates+=("${HOME}"/opt/ghidra_*_DEV "${HOME}"/opt/ghidra_* )
    candidates+=(/opt/ghidra_* /opt/ghidra)
    local c
    for c in "${candidates[@]}"; do
        [[ -x "${c}/ghidraRun" ]] && { printf '%s\n' "$c"; return 0; }
    done
    return 1
}

GHIDRA_DIR="$(find_ghidra || true)"
[[ -n "$GHIDRA_DIR" ]] || die "Could not find a Ghidra install. Set GHIDRA_INSTALL_DIR to the directory containing ghidraRun."

if [[ -n "$PROJECT_ARG" && ! -e "$PROJECT_ARG" ]]; then
    warn "Project path '$PROJECT_ARG' does not exist yet — launching without it; create/open the project via MCP once the server is up."
    PROJECT_ARG=""
fi

LOG="${TMPDIR:-/tmp}/ghidra_mcp_launch.log"
msg "Launching Ghidra (${GHIDRA_DIR}/ghidraRun)${PROJECT_ARG:+ with project ${PROJECT_ARG}} ..."
msg "Launch log: ${LOG}"

# Detach into a new session so the GUI/JVM survives this script and its caller
# (the MCP bridge) exiting. ghidraRun itself backgrounds the JVM, but setsid
# guarantees it is reparented away from our process group.
if [[ -n "$PROJECT_ARG" ]]; then
    setsid bash -c '"$0"/ghidraRun "$1" >"$2" 2>&1' "$GHIDRA_DIR" "$PROJECT_ARG" "$LOG" </dev/null &
else
    setsid bash -c '"$0"/ghidraRun >"$1" 2>&1' "$GHIDRA_DIR" "$LOG" </dev/null &
fi
disown || true

msg "Waiting up to ${TIMEOUT}s for the server at ${SERVER_URL}/ ..."
deadline=$(( SECONDS + TIMEOUT ))
while (( SECONDS < deadline )); do
    if server_up; then
        msg "Ghidra MCP server is up at ${SERVER_URL}/"
        exit 0
    fi
    sleep 2
done

warn "Timed out after ${TIMEOUT}s waiting for the server."
warn "Ghidra may still be starting (cold JVM + analysis can be slow). Re-run with --status, or check the log:"
warn "  tail -n 40 ${LOG}"
warn "Note: the server only starts once a CodeBrowser tool with GhidraMCPPlugin is open. If a fresh project"
warn "opened with no program, open any program in the CodeBrowser (or import one) to start the server."
exit 1
