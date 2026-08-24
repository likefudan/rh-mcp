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
# Exit codes: 0 dispatched or deliberately skipped, 1 could not decide.

set -euo pipefail

REPO="likefudan/rh-mcp"
WORKFLOW="manifest-refresh.yml"
LOG_DIR="${HOME}/Library/Logs/rh-mcp"
LOG="${LOG_DIR}/local-refresh-trigger.log"

# launchd gives a minimal PATH; Homebrew and the user's tools are not on it.
export PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"

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
  say "no network yet; nothing dispatched (launchd will try again tomorrow)"
  exit 0
fi

today="$(date -u '+%Y-%m-%d')"

# Any run today at all — success, failure, or still going. A failure today is
# still a run today: re-dispatching would stack a second job onto a runner that
# just failed, and the concurrency group would serialise them anyway.
existing="$(gh run list --repo "${REPO}" --workflow "${WORKFLOW}" --limit 20 \
  --json createdAt,conclusion,status \
  --jq "[.[] | select(.createdAt[0:10] == \"${today}\")] | length" 2>/dev/null || echo "unknown")"

if [ "${existing}" = "unknown" ]; then
  say "could not read run history; nothing dispatched"
  exit 1
fi

if [ "${existing}" -gt 0 ]; then
  say "already ${existing} run(s) today (${today}); nothing dispatched"
  exit 0
fi

if gh workflow run "${WORKFLOW}" --repo "${REPO}" >/dev/null 2>&1; then
  say "dispatched ${WORKFLOW}"
  exit 0
fi

say "dispatch failed; nothing was started"
exit 1
