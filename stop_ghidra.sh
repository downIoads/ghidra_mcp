#!/usr/bin/env bash
# Stop every Ghidra GUI owned by the current user, including instances whose
# MCP HTTP plugin never started or is stuck behind a modal dialog.
set -euo pipefail

SERVER_URL="${GHIDRA_SERVER_URL:-http://127.0.0.1:8080/}"
SERVER_URL="${SERVER_URL%/}"
TIMEOUT="${GHIDRA_STOP_TIMEOUT:-10}"

msg()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!! \033[0m %s\n' "$*" >&2; }

if ! [[ "$TIMEOUT" =~ ^[0-9]+$ ]]; then
    TIMEOUT=10
fi
(( TIMEOUT > 10 )) && TIMEOUT=10
(( TIMEOUT < 1 )) && TIMEOUT=1

ghidra_pids() {
    ps -u "${UID}" -o pid=,args= | while read -r pid args; do
        # Tokenize argv and only accept known executable/main-class layouts.
        # This deliberately does not match a shell -c command which merely
        # contains the words ghidraRun or ghidra.GhidraRun in its script text.
        read -r -a argv <<<"$args"
        argv0="${argv[0]:-}"
        argv1="${argv[1]:-}"
        matched=0
        case "${argv0##*/}" in
            java)
                for token in "${argv[@]:1}"; do
                    [[ "$token" == "ghidra.Ghidra" ]] && matched=1
                done
                ;;
            bash|sh)
                if [[ "${argv1##*/}" == "launch.sh" || "${argv1##*/}" == "ghidraRun" ]]; then
                    matched=1
                fi
                ;;
            ghidraRun|launch.sh)
                matched=1
                ;;
        esac
        (( matched )) && printf '%s\n' "$pid"
    done | sort -un
}

server_up() {
    curl -fsS --connect-timeout 0.2 --max-time 0.5 "${SERVER_URL}/ready" >/dev/null 2>&1
}

clean_requested=0
if server_up; then
    clean_requested=1
    msg "Requesting a clean Ghidra shutdown"
    curl -fsS --connect-timeout 0.2 --max-time 1 -X POST \
        "${SERVER_URL}/shutdown" >/dev/null 2>&1 || true
fi

if (( clean_requested )); then
    grace_seconds=$((TIMEOUT - 5))
    (( grace_seconds < 1 )) && grace_seconds=1
    (( grace_seconds > 3 )) && grace_seconds=3
    deadline=$((SECONDS + grace_seconds))
else
    # With no HTTP plugin there is no clean-shutdown path to wait for.
    deadline=$SECONDS
fi
while (( SECONDS < deadline )); do
    mapfile -t running < <(ghidra_pids)
    (( ${#running[@]} == 0 )) && break
    sleep 0.2
done

mapfile -t running < <(ghidra_pids)
if (( ${#running[@]} > 0 )); then
    warn "Stopping remaining Ghidra process(es): ${running[*]}"
    kill -TERM "${running[@]}" 2>/dev/null || true
    term_deadline=$((SECONDS + 1))
    while (( SECONDS < term_deadline )); do
        mapfile -t running < <(ghidra_pids)
        (( ${#running[@]} == 0 )) && break
        sleep 0.1
    done
fi

mapfile -t running < <(ghidra_pids)
if (( ${#running[@]} > 0 )); then
    warn "Force-stopping unresponsive Ghidra process(es): ${running[*]}"
    kill -KILL "${running[@]}" 2>/dev/null || true
fi

# Remove any detached launcher units after their processes are gone.
mapfile -t units < <(systemctl --user list-units --all --plain --no-legend \
    'ghidra-mcp-*' 2>/dev/null | awk '{ print $1 }')
if (( ${#units[@]} > 0 )); then
    timeout 2 systemctl --user stop "${units[@]}" >/dev/null 2>&1 || true
    timeout 2 systemctl --user reset-failed "${units[@]}" >/dev/null 2>&1 || true
fi

mapfile -t running < <(ghidra_pids)
if (( ${#running[@]} > 0 )); then
    warn "Unable to stop Ghidra process(es): ${running[*]}"
    exit 1
fi

msg "All Ghidra instances are stopped"
