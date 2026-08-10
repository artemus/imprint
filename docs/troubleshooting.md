# Troubleshooting

## Installer cannot create a virtual environment

Install a complete Python 3.10 or newer distribution with `venv` and `pip`, then rerun
the same artifact installer. On some Linux distributions, `python3-venv` is a
separate OS package. This is a dependency fix; manually copying source files is
not a durable substitute.

## Hook registration fails

The installer fails closed and leaves a timestamped settings backup. Validate
that the settings file is JSON and that its `hooks` value is an object whose
event values are lists. Restore the latest backup if another tool wrote invalid
JSON, correct that writer, and rerun the installer.

## Windows: which PowerShell is required

Windows PowerShell 5.1 is enough. The installer and the private-state ACL
hardening both run on the stock `powershell.exe` host; PowerShell 7 (`pwsh`) is
used automatically when present but is not required, and no version of Imprint
should ever ask you to install it.

If any command reports `unable to secure private Imprint state on Windows`, the
message names the PowerShell host that failed. Re-run the same command with
`IMPRINT_ACCEPTANCE_DEBUG=1` to see the underlying PowerShell error, which is
withheld by default because it can name private state paths:

```powershell
$env:IMPRINT_ACCEPTANCE_DEBUG = "1"; imprint health --deep
```

Releases up to and including 3.1.1 required PowerShell 7 for this path in
practice: the ACL script used a .NET-only type that does not exist on the .NET
Framework host, so `imprint health` and every hook failed on a stock Windows 11
machine. Installing PowerShell 7 worked around it. Later releases do not need it.

## Hooks report `hook_action_timeout`

The timeout body names the action and the deadline that was applied, for example
`{"error": "hook_action_timeout", "hook_action": "session-start",
"timeout_seconds": 60}`. Compare that deadline with how long the action really
takes outside the bridge:

```bash
imprint hook session-start < event.json
```

If the unbounded run succeeds and simply takes longer than the deadline — common
on Windows, where cold interpreter start plus security scanning can exceed a
minute — raise `hook_timeout_seconds` in config (1–300, preserved across
reinstall) or set `IMPRINT_HOOK_TIMEOUT_SECONDS` for one process. Do not patch
the installed package: an attested file must stay byte-identical.

If the unbounded run also fails or hangs, the deadline is reporting a real
fault; fix that instead of widening the deadline.

## Health is degraded

Read the structured status and counts. Missing config, denied filesystem access,
corrupt spool inputs, a disabled compiler, or database integrity failure require
different fixes. Health reports never include captured text. Preserve corrupt
inputs and the database before repair.

`compiler_state: absent` is not one of those failures. It reports that the
exclusive compiler lock is not held at that instant, which is the normal idle
state; the same fact is reported in plain language as
`compiler_state_label: idle`. No resident compiler service or scheduled task
exists to be missing. Only `compiler_state: invalid` degrades health.

## `log` returned zero events for today

`imprint log --date` takes a UTC calendar date. In any timezone west of UTC, an
evening session has already crossed into the next UTC day, so the local date is
the wrong query and returns nothing. Re-run without `--date`, which defaults to
today in UTC, before treating an empty result as a capture failure. See the
`log` section of the README for portable shell and PowerShell examples.

## Deep health reports `spool_stale`

`spool_stale` counts only **pending** spool inputs. An input that has been
compiled keeps a hash-verified acknowledgement under
`runtime/acknowledgements/<node>/`, and retention deliberately keeps that copy
for `spool_retention_days` (minimum one day) — far longer than the one-hour
stale threshold. Those copies appear as `acknowledged_retained_spool_depth` and
never degrade health.

Read `pending_spool_depth` and `oldest_pending_spool_age_seconds` to see the
real backlog. If pending work is genuinely old, run `imprint compile --once` and
read its counts. `imprint spool prune` removes acknowledged copies once they
pass retention; pruning is never automatic.

Releases up to and including 3.1.1 measured staleness across every spool file,
so a correctly acknowledged copy between one hour and one day old reported
`degraded` with nothing wrong.

## Cloud-sync root refused

Move the data root to a local non-synchronized directory and update config. A
manual bypass would reintroduce concurrent-writer and partial-sync corruption;
the permanent fix is to keep the canonical database local and move immutable
exchange artifacts separately.
