#!/usr/bin/env bash
# Install / update the Ghidra MCP bridge and Ghidra extension, then register
# the bridge with MCP hosts. Idempotent — safe to re-run after pulling changes
# or editing the source.
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${PROJECT_DIR}/.venv"
PY="${VENV_DIR}/bin/python"
BRIDGE="${PROJECT_DIR}/bridge_mcp_ghidra.py"
MCP_NAME="ghidra"
SCOPE="${GHIDRA_MCP_SCOPE:-user}"           # override: GHIDRA_MCP_SCOPE=local ./install.sh
GHIDRA_VERSION="${GHIDRA_VERSION:-ghidra_12.2_DEV}"
GHIDRA_EXT_DIR="${GHIDRA_EXT_DIR:-${HOME}/.config/ghidra/${GHIDRA_VERSION}/Extensions}"
GHIDRA_SERVER_URL="${GHIDRA_SERVER_URL:-http://127.0.0.1:8080/}"
LOCK_DIR="${PROJECT_DIR}/.install.lock"

msg()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!! \033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31mxx \033[0m %s\n' "$*" >&2; exit 1; }

take_lock() {
    if mkdir "$LOCK_DIR" 2>/dev/null; then
        printf '%s\n' "$$" >"${LOCK_DIR}/pid"
        trap 'rm -rf "$LOCK_DIR"' EXIT
        return
    fi

    local old_pid=""
    if [[ -r "${LOCK_DIR}/pid" ]]; then
        old_pid="$(<"${LOCK_DIR}/pid")"
    fi
    if [[ "$old_pid" =~ ^[0-9]+$ ]] && kill -0 "$old_pid" 2>/dev/null; then
        warn "Another install.sh is already running (pid ${old_pid}); exiting."
        exit 1
    fi

    warn "Removing stale install lock."
    rm -rf "$LOCK_DIR"
    mkdir "$LOCK_DIR"
    printf '%s\n' "$$" >"${LOCK_DIR}/pid"
    trap 'rm -rf "$LOCK_DIR"' EXIT
}

clean_python_env() {
    if [[ -n "${VIRTUAL_ENV:-}" && "${VIRTUAL_ENV}" != "${VENV_DIR}" ]]; then
        warn "Ignoring active virtualenv: ${VIRTUAL_ENV}"
        warn "Using project virtualenv: ${VENV_DIR}"
        unset VIRTUAL_ENV
    fi
    hash -r 2>/dev/null || true
}

bridge_pids() {
    # Match processes whose argv0 is a python interpreter running our bridge.
    # The argv0 check avoids matching shells/editors that merely mention the
    # script path in their arguments. Excludes this script's own PID.
    ps -eo pid=,args= | while read -r pid args; do
        [[ "$pid" == "$$" ]] && continue
        # shellcheck disable=SC2086
        set -- $args
        local argv0="${1:-}"
        case "$argv0" in
            *python*|*Python*) ;;
            *) continue ;;
        esac
        case "$args" in
            *bridge_mcp_ghidra.py*) printf '%s\n' "$pid" ;;
        esac
    done
}

stop_running_bridges() {
    mapfile -t pids < <(bridge_pids | sort -u)
    if (( ${#pids[@]} == 0 )); then
        return
    fi

    msg "Stopping existing Ghidra MCP bridge process(es): ${pids[*]}"
    kill -TERM "${pids[@]}" 2>/dev/null || true

    local deadline=$((SECONDS + 5))
    while (( SECONDS < deadline )); do
        local alive=()
        for pid in "${pids[@]}"; do
            if kill -0 "$pid" 2>/dev/null; then
                alive+=("$pid")
            fi
        done
        if (( ${#alive[@]} == 0 )); then
            return
        fi
        sleep 0.2
    done

    warn "Force-stopping stuck Ghidra MCP bridge process(es)."
    kill -KILL "${pids[@]}" 2>/dev/null || true
}

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || die "'$1' not found on PATH. ${2:-}"
}

take_lock
clean_python_env
stop_running_bridges

# 1. Sanity checks
require_cmd mvn    "Install Maven to build the Ghidra extension."
require_cmd java   "Install Java 21 to build the Ghidra extension."
require_cmd python3 "Install Python 3.10+ for the MCP bridge."

if [[ ! -d "${PROJECT_DIR}/lib" ]] || ! ls "${PROJECT_DIR}/lib/"*.jar >/dev/null 2>&1; then
    die "No jars found in ${PROJECT_DIR}/lib. Copy the Ghidra jars listed in README.md first."
fi

# 2. Build the Ghidra extension
msg "Building Ghidra extension with Maven"
( cd "$PROJECT_DIR" && mvn -q clean package )

EXT_ZIP="$(ls -1t "${PROJECT_DIR}/target/"GhidraMCP-*.zip 2>/dev/null | head -n1 || true)"
[[ -n "$EXT_ZIP" && -f "$EXT_ZIP" ]] || die "Build did not produce a GhidraMCP-*.zip in target/."

# 3. Install the extension into the user's Ghidra config
if [[ ! -d "$(dirname "$GHIDRA_EXT_DIR")" ]]; then
    warn "Ghidra config dir not found: $(dirname "$GHIDRA_EXT_DIR")"
    warn "Run Ghidra at least once, or set GHIDRA_VERSION / GHIDRA_EXT_DIR."
else
    mkdir -p "$GHIDRA_EXT_DIR"
    msg "Installing extension into ${GHIDRA_EXT_DIR}/GhidraMCP"
    rm -rf "${GHIDRA_EXT_DIR}/GhidraMCP"
    # The zip contains a top-level GhidraMCP/ directory.
    if command -v unzip >/dev/null 2>&1; then
        unzip -q -o "$EXT_ZIP" -d "$GHIDRA_EXT_DIR"
    else
        ( cd "$GHIDRA_EXT_DIR" && python3 -m zipfile -e "$EXT_ZIP" . )
    fi

    if pgrep -f 'ghidra.*Ghidra' >/dev/null 2>&1 || pgrep -f 'GhidraRun' >/dev/null 2>&1; then
        warn "Ghidra is currently running — restart it to pick up the new extension."
    fi
fi

# 4. Python venv + dependencies
if [[ ! -x "$PY" ]]; then
    msg "Creating venv at ${VENV_DIR}"
    python3 -m venv "$VENV_DIR"
fi

msg "Installing Python dependencies"
"$PY" -m pip install --quiet --upgrade pip
"$PY" -m pip install --quiet -r "${PROJECT_DIR}/requirements.txt"

# 5. Smoke-import so we fail fast if the bridge is broken
msg "Verifying bridge imports cleanly"
"$PY" -c "
import importlib.util, pathlib
p = pathlib.Path('${BRIDGE}')
spec = importlib.util.spec_from_file_location('bridge_mcp_ghidra', p)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
print(f'   {len(mod.mcp._tool_manager.list_tools())} tools registered')
"

# 6. Register with known MCP hosts
if command -v claude >/dev/null 2>&1; then
    # Drop stale registrations so the command path always reflects this checkout.
    claude mcp remove "$MCP_NAME" --scope "$SCOPE" >/dev/null 2>&1 || true
    claude mcp remove "$MCP_NAME" >/dev/null 2>&1 || true

    msg "Registering '${MCP_NAME}' with Claude Code (scope: ${SCOPE})"
    claude mcp add "$MCP_NAME" --scope "$SCOPE" -- \
        "$PY" "$BRIDGE" --ghidra-server "$GHIDRA_SERVER_URL"

    echo
    msg "Current registrations:"
    claude mcp list | sed 's/^/    /'
    echo
    msg "Toggle '${MCP_NAME}' in the Claude Code VS Code extension's MCP panel."
else
    warn "'claude' CLI not on PATH — skipping registration."
    warn "Run this once it's installed:"
    warn "  claude mcp add ${MCP_NAME} --scope ${SCOPE} -- ${PY} ${BRIDGE} --ghidra-server ${GHIDRA_SERVER_URL}"
fi

if command -v codex >/dev/null 2>&1; then
    codex mcp remove "$MCP_NAME" >/dev/null 2>&1 || true

    msg "Registering '${MCP_NAME}' with Codex"
    codex mcp add "$MCP_NAME" -- "$PY" "$BRIDGE" --ghidra-server "$GHIDRA_SERVER_URL"
else
    warn "'codex' CLI not on PATH — skipping registration."
    warn "Run this once it's installed:"
    warn "  codex mcp add ${MCP_NAME} -- ${PY} ${BRIDGE} --ghidra-server ${GHIDRA_SERVER_URL}"
fi
