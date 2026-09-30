#!/bin/bash
# Dispatch the Robinhood manifest refresh from the machine that can actually
# run it.
#
# The `discover` job needs the Keychain credential, so it only runs on this
# Mac. GitHub's `schedule:` trigger cannot see whether this Mac is awake, and
# a queued job that nobody claims becomes a timeout failure that says nothing
# about the manifest. launchd can see it: a missed StartCalendarInterval is
# re-run at the next wake, so this fires when the machine is genuinely up.
#
# Idempotence is checked against GitHub, not against a local state file. A
# state file records what this script believes it did; the API records what
# actually ran, and those differ exactly when something went wrong — a failed
# dispatch, a cleared cache, a run triggered by hand. The API is the one worth
# asking.
#
# The LaunchAgent invokes this hourly. One successful or active run suppresses
# all later invocations that UTC day. A failed run may be retried, but never
# more than MAX_DAILY_ATTEMPTS times. After dispatch this process keeps macOS
# awake until the workflow finishes; otherwise the credential-bearing runner
# can claim the job and immediately disappear into sleep.
#
# Exit codes: 0 dispatched or deliberately skipped, 1 could not decide.

set -euo pipefail

REPO="likefudan/rh-mcp"
WORKFLOW="manifest-refresh.yml"
MAX_DAILY_ATTEMPTS="${RH_MCP_MAX_DAILY_ATTEMPTS:-3}"
RUN_DISCOVERY_ATTEMPTS="${RH_MCP_RUN_DISCOVERY_ATTEMPTS:-180}"
RUN_DISCOVERY_DELAY="${RH_MCP_RUN_DISCOVERY_DELAY:-10}"
RUN_WATCH_ATTEMPTS="${RH_MCP_RUN_WATCH_ATTEMPTS:-120}"
RUN_WATCH_DELAY="${RH_MCP_RUN_WATCH_DELAY:-15}"
LOG_DIR="${HOME}/Library/Logs/rh-mcp"
LOG="${LOG_DIR}/local-refresh-trigger.log"

# launchd gives a minimal PATH; Homebrew and the user's tools are not on it.
export PATH="${RH_MCP_TRIGGER_PATH:-/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin}"

mkdir -p "${LOG_DIR}"
chmod 700 "${LOG_DIR}" 2>/dev/null || true

say() { printf '%s  %s\n' "$(date '+%Y-%m-%dT%H:%M:%S%z')" "$1" >>"${LOG}"; }

# Keep the log from growing without bound; this runs daily forever.
if [ -f "${LOG}" ] && [ "$(wc -c <"${LOG}")" -gt 262144 ]; then
  tail -c 131072 "${LOG}" >"${LOG}.trimmed" && mv "${LOG}.trimmed" "${LOG}"
fi

if ! command -v gh >/dev/null 2>&1; then
  say "gh not found on PATH; nothing dispatched"
  exit 1
fi

# Being awake is not being online. A wake-from-sleep run reaches this line
# before Wi-Fi has associated, and a dispatch attempted then fails in a way
# that looks like a credential or permission problem.
if ! curl --silent --show-error --fail --max-time 10 \
      -o /dev/null https://api.github.com/rate_limit 2>/dev/null; then
  say "no network yet; nothing dispatched (launchd will retry hourly)"
  exit 0
fi

today="$(date -u '+%Y-%m-%d')"

# An active or successful run is authoritative completion for today. Failed or
# cancelled runs are attempts, not success: the hourly trigger may retry them
# after the previous run has fully stopped.
active_or_success="$(gh run list --repo "${REPO}" --workflow "${WORKFLOW}" --limit 20 \
  --json createdAt,conclusion,status \
  --jq "[.[] | select(.createdAt[0:10] == \"${today}\" and (.status != \"completed\" or .conclusion == \"success\"))] | length" \
  2>/dev/null || echo "unknown")"

if [ "${active_or_success}" = "unknown" ]; then
  say "could not read run history; nothing dispatched"
  exit 1
fi

if [ "${active_or_success}" -gt 0 ]; then
  say "already ${active_or_success} active/successful run(s) today (${today}); nothing dispatched"
  exit 0
fi

attempts="$(gh run list --repo "${REPO}" --workflow "${WORKFLOW}" --limit 20 \
  --json createdAt \
  --jq "[.[] | select(.createdAt[0:10] == \"${today}\")] | length" \
  2>/dev/null || echo "unknown")"
if [ "${attempts}" = "unknown" ]; then
  say "could not count today's attempts; nothing dispatched"
  exit 1
fi
if [ "${attempts}" -ge "${MAX_DAILY_ATTEMPTS}" ]; then
  say "daily attempt limit reached (${attempts}/${MAX_DAILY_ATTEMPTS}); nothing dispatched"
  exit 1
fi

dispatch_id="$(uuidgen | tr '[:upper:]' '[:lower:]')"
run_title="Robinhood manifest refresh ${dispatch_id}"

# Establish the assertion before dispatch. If the API accepts the dispatch but
# correlation calls fail, the job still has the full bounded discovery window
# to start and finish without the Mac sleeping underneath it.
caffeinate -dimsu -w "$$" >/dev/null 2>&1 &
wake_pid=$!
/bin/sleep 0.1
if ! kill -0 "${wake_pid}" 2>/dev/null; then
  say "could not establish the macOS wake assertion; refusing to dispatch"
  exit 1
fi
cleanup_wake() {
  kill "${wake_pid}" 2>/dev/null || true
  wait "${wake_pid}" 2>/dev/null || true
}
trap cleanup_wake EXIT

if ! gh workflow run "${WORKFLOW}" --repo "${REPO}" \
  -f "dispatch_id=${dispatch_id}" >/dev/null 2>&1; then
  say "dispatch failed; nothing was started"
  exit 1
fi

run_id=""
probe=0
while [ "${probe}" -lt "${RUN_DISCOVERY_ATTEMPTS}" ]; do
  candidate="$(gh run list --repo "${REPO}" --workflow "${WORKFLOW}" --limit 20 \
    --json databaseId,displayTitle \
    --jq ".[] | select(.displayTitle == \"${run_title}\") | .databaseId" \
    2>/dev/null || echo "unknown")"
  if [ "${candidate}" != "unknown" ] && [ -n "${candidate}" ]; then
    run_id="${candidate}"
    break
  fi
  probe=$((probe + 1))
  sleep "${RUN_DISCOVERY_DELAY}"
done

if [ -z "${run_id}" ]; then
  say "dispatched ${WORKFLOW}, but could not identify its run id"
  exit 1
fi

say "dispatched ${WORKFLOW} as run ${run_id}; holding wake assertion until completion"
watch_probe=0
while [ "${watch_probe}" -lt "${RUN_WATCH_ATTEMPTS}" ]; do
  state="$(gh run view "${run_id}" --repo "${REPO}" \
    --json status,conclusion \
    --jq '.status + ":" + (.conclusion // "")' 2>/dev/null || echo "unknown")"
  case "${state}" in
    completed:success)
      say "run ${run_id} completed successfully"
      exit 0
      ;;
    completed:*)
      say "run ${run_id} completed unsuccessfully; a later hourly invocation may retry"
      exit 1
      ;;
    *)
      # A transient API/auth/network failure is not a workflow result. Keep the
      # wake assertion and retry until the workflow's own timeout has elapsed.
      watch_probe=$((watch_probe + 1))
      sleep "${RUN_WATCH_DELAY}"
      ;;
  esac
done

say "run ${run_id} state remained unknown; wake hold expired after bounded monitoring"
exit 1
