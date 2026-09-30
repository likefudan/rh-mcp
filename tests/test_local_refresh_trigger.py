from __future__ import annotations

import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).parents[1]
TRIGGER = ROOT / "contrib/local_refresh_trigger.sh"
PLIST = ROOT / "contrib/com.likefudan.rh-mcp.refresh-trigger.plist"


def _write_executable(path: Path, body: str) -> None:
    path.write_text("#!/bin/bash\nset -eu\n" + body, encoding="utf-8")
    path.chmod(0o755)


def _run_trigger(
    tmp_path: Path,
    *,
    active_or_success: int = 0,
    attempts: int = 0,
    run_state: str = "completed:success",
    transient_views: int = 0,
    correlate: bool = True,
) -> subprocess.CompletedProcess[str]:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    state = tmp_path / "state"
    view_count = tmp_path / "view-count"
    calls = tmp_path / "calls"
    _write_executable(fake_bin / "curl", "exit 0\n")
    _write_executable(fake_bin / "sleep", ":\n")
    _write_executable(
        fake_bin / "date",
        """if [ "${1:-}" = "-u" ]; then
  echo 2026-09-30
else
  echo 2026-09-30T12:00:00+0000
fi
""",
    )
    correlation_flag = "1" if correlate else "0"
    _write_executable(
        fake_bin / "gh",
        f"""printf '%s\\n' "$*" >>"{calls}"
if [ "$1 $2" = "run list" ]; then
  case "$*" in
    *"createdAt,conclusion,status"*) echo {active_or_success} ;;
    *"--json createdAt "*) echo {attempts} ;;
    *"databaseId,displayTitle"*)
      if [ "{correlation_flag}" = "1" ] && [ -f "{state}" ]; then
        dispatch_id=$(cat "{state}")
        case "$*" in
          *"Robinhood manifest refresh $dispatch_id"*) echo 222 ;;
          *) exit 2 ;;
        esac
      fi ;;
    *) exit 2 ;;
  esac
  exit 0
fi
if [ "$1 $2" = "workflow run" ]; then
  for arg in "$@"; do
    case "$arg" in dispatch_id=*) printf '%s' "${{arg#dispatch_id=}}" >"{state}" ;; esac
  done
  exit 0
fi
if [ "$1 $2" = "run view" ]; then
  count=0
  if [ -f "{view_count}" ]; then count=$(cat "{view_count}"); fi
  count=$((count + 1))
  printf '%s' "$count" >"{view_count}"
  if [ "$count" -le "{transient_views}" ]; then exit 1; fi
  echo "{run_state}"
  exit 0
fi
exit 2
""",
    )
    _write_executable(
        fake_bin / "caffeinate",
        f"""printf '%s\\n' "$*" >>"{calls}"
/bin/sleep 60
""",
    )
    env = os.environ | {
        "HOME": str(tmp_path / "home"),
        "RH_MCP_TRIGGER_PATH": f"{fake_bin}:/usr/bin:/bin",
        "RH_MCP_RUN_DISCOVERY_ATTEMPTS": "2",
        "RH_MCP_RUN_DISCOVERY_DELAY": "0",
        "RH_MCP_RUN_WATCH_ATTEMPTS": "4",
        "RH_MCP_RUN_WATCH_DELAY": "0",
    }
    return subprocess.run(("/bin/bash", str(TRIGGER)), env=env, text=True, capture_output=True)


def _log(tmp_path: Path) -> str:
    return (tmp_path / "home/Library/Logs/rh-mcp/local-refresh-trigger.log").read_text()


def _calls(tmp_path: Path) -> str:
    path = tmp_path / "calls"
    return path.read_text() if path.exists() else ""


def test_active_or_successful_daily_run_suppresses_dispatch(tmp_path: Path) -> None:
    result = _run_trigger(tmp_path, active_or_success=1)

    assert result.returncode == 0
    assert "active/successful run(s)" in _log(tmp_path)
    assert "workflow run" not in _calls(tmp_path)
    assert "run view" not in _calls(tmp_path)


def test_failed_run_is_retried_and_mac_stays_awake_until_success(tmp_path: Path) -> None:
    result = _run_trigger(tmp_path, attempts=1)

    assert result.returncode == 0
    calls = _calls(tmp_path)
    assert "workflow run manifest-refresh.yml" in calls
    assert "dispatch_id=" in calls
    assert "run view 222 --repo likefudan/rh-mcp" in calls
    log = _log(tmp_path)
    assert "holding wake assertion until completion" in log
    assert "run 222 completed successfully" in log


def test_unsuccessful_watched_run_allows_a_later_hourly_retry(tmp_path: Path) -> None:
    result = _run_trigger(tmp_path, attempts=2, run_state="completed:failure")

    assert result.returncode == 1
    assert "a later hourly invocation may retry" in _log(tmp_path)


def test_transient_view_failure_keeps_wake_hold_and_does_not_invent_failure(
    tmp_path: Path,
) -> None:
    result = _run_trigger(tmp_path, attempts=1, transient_views=2)

    assert result.returncode == 0
    assert _calls(tmp_path).count("run view 222") == 3
    assert "completed successfully" in _log(tmp_path)


def test_correlation_failure_is_wake_protected_for_the_bounded_search(
    tmp_path: Path,
) -> None:
    result = _run_trigger(tmp_path, attempts=1, correlate=False)

    assert result.returncode == 1
    assert "-dimsu -w" in _calls(tmp_path)
    assert "could not identify its run id" in _log(tmp_path)


def test_daily_attempt_limit_prevents_retry_storm(tmp_path: Path) -> None:
    result = _run_trigger(tmp_path, attempts=3)

    assert result.returncode == 1
    assert "daily attempt limit reached (3/3)" in _log(tmp_path)
    assert "workflow run" not in _calls(tmp_path)


def test_launch_agent_runs_hourly_at_load_instead_of_one_fragile_clock_time() -> None:
    text = PLIST.read_text(encoding="utf-8")
    trigger = TRIGGER.read_text(encoding="utf-8")

    assert "<key>StartInterval</key>" in text
    assert "<integer>3600</integer>" in text
    assert "<key>RunAtLoad</key>\n  <true/>" in text
    assert "StartCalendarInterval" not in text
    assert 'caffeinate -dimsu -w "$$"' in trigger
    assert 'kill -0 "${wake_pid}"' in trigger
