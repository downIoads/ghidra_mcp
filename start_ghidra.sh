#!/usr/bin/env bash
# Launch a deterministic CodeBrowser session with GhidraMCP enabled.
set -euo pipefail

SERVER_URL="${GHIDRA_SERVER_URL:-http://127.0.0.1:8080/}"
SERVER_URL="${SERVER_URL%/}"
TIMEOUT="${GHIDRA_START_TIMEOUT:-10}"
STATUS_ONLY=0
PROJECT_PATH=""
PROGRAM_PATH=""

msg()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!! \033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31mxx \033[0m %s\n' "$*" >&2; exit 1; }

while (( $# > 0 )); do
    case "$1" in
        --status) STATUS_ONLY=1; shift ;;
        --project) [[ $# -ge 2 ]] || die "--project requires a .gpr path"; PROJECT_PATH="$2"; shift 2 ;;
        --program) [[ $# -ge 2 ]] || die "--program requires a project path such as /binary"; PROGRAM_PATH="$2"; shift 2 ;;
        -h|--help) sed -n '1,100p' "$0"; exit 0 ;;
        *) die "Unexpected argument: $1" ;;
    esac
done

if ! [[ "$TIMEOUT" =~ ^[0-9]+$ ]]; then
    TIMEOUT=10
fi
(( TIMEOUT > 10 )) && TIMEOUT=10
(( TIMEOUT < 1 )) && TIMEOUT=1
[[ -z "$PROGRAM_PATH" || -n "$PROJECT_PATH" ]] || die "--program also requires --project."

server_up() {
    curl -fsS --connect-timeout 0.25 --max-time 0.5 "${SERVER_URL}/ready" >/dev/null 2>&1
}

handle_startup_dialogs() {
    [[ -n "${DISPLAY:-}" ]] || return 0
    command -v xdotool >/dev/null 2>&1 || return 0

    local id window_class

    # Ghidra's first-run agreement dialog intentionally has the X11 title
    # " " (one space). Focus moves from the license text to "I Agree" with
    # one Tab, then Return activates it.
    while read -r id; do
        [[ -n "$id" ]] || continue
        window_class="$(xprop -id "$id" WM_CLASS 2>/dev/null || true)"
        [[ "$window_class" == *ghidra-Ghidra* ]] || continue
        xdotool windowactivate --sync "$id" >/dev/null 2>&1 || continue
        xdotool key --clearmodifiers Tab Return >/dev/null 2>&1 || true
    done < <(xdotool search --onlyvisible --name '^ $' 2>/dev/null || true)

    # Imported programs are marked "don't ask" by the plugin. This is a
    # fallback for older/external projects: decline the modal and let MCP
    # start analysis explicitly, so the UI never stalls unattended.
    while read -r id; do
        [[ -n "$id" ]] || continue
        xdotool windowactivate --sync "$id" >/dev/null 2>&1 || continue
        xdotool key --clearmodifiers Escape >/dev/null 2>&1 || true
    done < <(xdotool search --onlyvisible --name '^Analyze\?$' 2>/dev/null || true)

    # Tip of the Day is another modal shown on fresh profiles. Escape closes
    # it while preserving the user's normal preference for future launches.
    while read -r id; do
        [[ -n "$id" ]] || continue
        xdotool windowactivate --sync "$id" >/dev/null 2>&1 || continue
        xdotool key --clearmodifiers Escape >/dev/null 2>&1 || true
    done < <(xdotool search --onlyvisible --name '^Tip of the Day$' 2>/dev/null || true)
}

watch_startup_dialogs() {
    local watcher_deadline=$((SECONDS + TIMEOUT))
    while (( SECONDS < watcher_deadline )); do
        handle_startup_dialogs
        sleep 0.1
    done
}

if server_up; then
    msg "Ghidra MCP server already listening at ${SERVER_URL}/"
    exit 0
fi

if (( STATUS_ONLY )); then
    warn "No Ghidra MCP server at ${SERVER_URL}/"
    exit 1
fi

find_ghidra() {
    if [[ -n "${GHIDRA_INSTALL_DIR:-}" && -x "${GHIDRA_INSTALL_DIR}/ghidraRun" ]]; then
        printf '%s\n' "$GHIDRA_INSTALL_DIR"
        return 0
    fi
    local candidate
    for candidate in "${HOME}"/opt/ghidra_*_DEV "${HOME}"/opt/ghidra_* /opt/ghidra_* /opt/ghidra; do
        if [[ -x "${candidate}/ghidraRun" ]]; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done
    return 1
}

GHIDRA_DIR="$(find_ghidra || true)"
[[ -n "$GHIDRA_DIR" ]] || die "Could not find Ghidra; set GHIDRA_INSTALL_DIR."

# The bootstrap program forces Ghidra to launch CodeBrowser even when the last
# project was closed and no tool session is available to restore.
STATE_ROOT="${GHIDRA_MCP_STATE_DIR:-${TMPDIR:-/tmp}/ghidra-mcp-${UID}}"
BOOTSTRAP_NAME="bootstrap-v2"
BOOTSTRAP_GPR="${STATE_ROOT}/${BOOTSTRAP_NAME}.gpr"
BOOTSTRAP_REP="${STATE_ROOT}/${BOOTSTRAP_NAME}.rep"
BOOTSTRAP_PROGRAM="true"

mkdir -p "$STATE_ROOT"
chmod 700 "$STATE_ROOT"
if [[ ! -f "$BOOTSTRAP_GPR" || ! -d "$BOOTSTRAP_REP" ]]; then
    msg "Creating one-time GhidraMCP bootstrap project"
    "${GHIDRA_DIR}/support/analyzeHeadless" "$STATE_ROOT" "$BOOTSTRAP_NAME" \
        -import /bin/true >/dev/null
fi

# Installation edits this file so the extension is enabled without a GUI
# checkbox. Re-apply it here in case Ghidra regenerated the tool config.
CONFIG_HOME="${XDG_CONFIG_HOME:-${HOME}/.config}"
python3 "$(dirname "$0")/configure_ghidra.py" \
    --config-home "$CONFIG_HOME" --version "ghidra_12.2" --strict >/dev/null \
    || die "CodeBrowser config is unavailable; reinstall GhidraMCP with ./install.sh."

if [[ -n "$PROJECT_PATH" ]]; then
    [[ -f "$PROJECT_PATH" ]] || die "Project does not exist: $PROJECT_PATH"
    [[ -n "$PROGRAM_PATH" ]] || die "--project requires --program so CodeBrowser and GhidraMCP start."
    [[ "$PROGRAM_PATH" == /* ]] || PROGRAM_PATH="/${PROGRAM_PATH}"
    TARGET="${PROJECT_PATH}:${PROGRAM_PATH}"
    msg "Launching Ghidra CodeBrowser for ${TARGET}"
else
    TARGET="${BOOTSTRAP_GPR}:/${BOOTSTRAP_PROGRAM}"
    msg "Launching Ghidra CodeBrowser bootstrap"
fi
UNIT_BASE="${GHIDRA_MCP_SYSTEMD_UNIT:-ghidra-mcp-backend}"
UNIT="${UNIT_BASE}-$$"
command -v systemd-run >/dev/null 2>&1 || die "systemd-run is required for reliable detached startup."

systemd_args=(--user --unit="$UNIT" --collect --quiet)
if [[ -n "${DISPLAY:-}" ]]; then
    systemd_args+=(--setenv="DISPLAY=${DISPLAY}")
fi
if [[ -n "${XAUTHORITY:-}" ]]; then
    systemd_args+=(--setenv="XAUTHORITY=${XAUTHORITY}")
fi
ghidra_runtime_dir="${XDG_RUNTIME_DIR:-/run/user/${UID}}"
ghidra_bus_address="${DBUS_SESSION_BUS_ADDRESS:-unix:path=${ghidra_runtime_dir}/bus}"
XDG_RUNTIME_DIR="$ghidra_runtime_dir" DBUS_SESSION_BUS_ADDRESS="$ghidra_bus_address" \
systemd-run "${systemd_args[@]}" \
    "${GHIDRA_DIR}/support/launch.sh" fg jdk Ghidra "" "" \
    ghidra.GhidraRun "$TARGET"

# Keep watching briefly after /ready becomes available because Ghidra can
# create the Analyze? modal just after the HTTP plugin starts. Redirect all
# descriptors so this bounded watcher never holds an MCP subprocess pipe open.
watch_startup_dialogs </dev/null >/dev/null 2>&1 &

deadline=$((SECONDS + TIMEOUT))
while (( SECONDS < deadline )); do
    if server_up; then
        msg "Ghidra MCP server is up at ${SERVER_URL}/"
        exit 0
    fi
    sleep 0.25
done

warn "Ghidra MCP did not start within ${TIMEOUT}s."
XDG_RUNTIME_DIR="$ghidra_runtime_dir" DBUS_SESSION_BUS_ADDRESS="$ghidra_bus_address" \
    journalctl --user -u "${UNIT}.service" -n 30 --no-pager >&2 2>/dev/null || true
exit 1
