# netgear-cm500-cli

Fetch and summarize status from a NETGEAR CM500 cable modem.

The CM500 web UI embeds its live DOCSIS values in JavaScript variables. This
tool fetches that page, parses the values, and renders a readable summary (or
JSON) for the connection, the downstream/upstream channel tables, and the
DOCSIS event log. Text output highlights out-of-spec signal values and severe
events; it is stdlib-only, with no third-party dependencies.

## Install

Requires Python 3.11+ and [uv](https://docs.astral.sh/uv/).

```sh
uv sync
```

## Usage

The modem requires admin credentials. Supply the password through the
`CM500_PASS` environment variable or the interactive prompt — it is never
accepted as a command-line argument, so it does not leak into shell history or
the process list.

```sh
# available subcommands and options (no modem connection)
uv run netgear-cm500-cli

# connection summary and channel tables
uv run netgear-cm500-cli status

# most recent event-log entries
uv run netgear-cm500-cli events

# gateway, LAN, and wireless status
uv run netgear-cm500-cli gateway

# voice/MTA status
uv run netgear-cm500-cli voice

# full-screen monitor mode (refresh every 5 seconds by default)
uv run netgear-cm500-cli status --monitor

# only errors from the event log, as JSON
uv run netgear-cm500-cli events --min-severity error --json
```

### Subcommands

- `status` — connection summary with downstream and upstream channel
  tables.
- `events` — most recent entries from the DOCSIS event log.
  - `-n, --limit N` — number of events to show (default: 20, `0` for all).
  - `-s, --min-severity LEVEL` — show only events at this severity or worse
    (`emergency`, `alert`, `critical`, `error`, `warning`, `notice`,
    `information`, `debug`).
- `gateway` — modem identification, cable and Internet port details, LAN
  status, wireless 2.4/5 GHz status, and system time/uptime.
- `voice` — voice line states and MTA provisioning details.
- `--monitor` — poll continuously and refresh the full current view.
- `--interval SECONDS` — monitor poll interval (default: `5`); must be a
  finite number greater than zero.

Monitor mode is text-only: `--json` is single-shot output and cannot be
combined with `--monitor`.

### Common options

A subcommand is required to fetch data. Without one, the tool displays help.

| Option | Default | Environment variable |
| --- | --- | --- |
| `--host` | `192.168.100.1` | `CM500_HOST` |
| `--user` | `admin` | `CM500_USER` |
| `--json` | text summary | — |
| `--no-color` | color on an interactive terminal | `NO_COLOR` |
| `--monitor` | one-shot fetch | — |
| `--interval` | `5` seconds | — |

Color is emitted only to an interactive terminal. It is suppressed for JSON,
pipes, `--no-color`, and the [`NO_COLOR`](https://no-color.org) convention.

In monitor mode, interactive terminals clear and redraw each successful poll.
When redirected to a file/pipe, snapshots are appended without terminal
control escape sequences and flushed after each refresh. Press `Ctrl-C` to
stop monitor mode.

### Optional 1Password wrapper

The utility itself has no 1Password integration. The standalone
`scripts/cm500_1password.sh` Bash wrapper retrieves the `username` and `password`
fields from a single item, then replaces itself with `netgear-cm500-cli`,
passing credentials through `CM500_USER` and `CM500_PASS`.
Requires Bash, `jq`, and the
[1Password CLI](https://developer.1password.com/docs/cli/) (`op`) installed
and signed in.

Run from the repository root; `uv run` makes the project's CLI available:

```sh
uv run ./scripts/cm500_1password.sh --item cm500-admin --vault Home -- status
uv run ./scripts/cm500_1password.sh --item cm500-admin -- events --json
uv run ./scripts/cm500_1password.sh --item cm500-admin -- gateway --monitor
```

If `netgear-cm500-cli` is already on your `PATH`, omit `uv run` and execute
`./scripts/cm500_1password.sh` directly.

`--vault` is optional; omit it to let `op` find the item across accessible
vaults. Use an item ID or specify a vault to disambiguate duplicate names.
All arguments after `--` are passed to the utility
unchanged; an explicit `--user` overrides the item's username. Item credentials
replace existing `CM500_USER` and `CM500_PASS` values for the child process
only. Lookup or validation failures stop execution without falling back to
other credentials. Credentials are not placed in command-line arguments,
printed, or written to temporary files, but are present in the child process
environment and accessible to processes permitted to inspect it.

The former `--op-item`, `--op-vault`, `CM500_OP_ITEM`, and `CM500_OP_VAULT`
integration has been removed; use this wrapper instead.

## Development

```sh
uv run pytest          # tests with coverage (80% gate)
uvx ruff check         # lint
uvx ruff format        # format
```
