# toolgate

A lightweight gate that runs as a hook for coding agents and uses CEL-based policies to allow / ask / deny each tool call. Supports **Claude Code / GitHub Copilot / Cursor**.

Policies are written against **capability** (`kind`) rather than agent-specific tool names, so a single policy is portable across all three agents. Shell commands are parsed as an AST and judged structurally.

> **Note**: toolgate is one layer of defense in depth, not complete control. Static analysis
> has fundamental limitations (see [§What It Can and Cannot Prevent](#what-it-can-and-cannot-prevent)).
> Use it together with isolation via OS / container / execution-user privileges.

## Installation

```console
$ go install github.com/mrtc0/toolgate/cmd/toolgate@latest
```

Or download a pre-built binary from [Releases](https://github.com/mrtc0/toolgate/releases).

## Setup

1. Place your user policy at `~/.config/toolgate/policy.yaml` (see [examples/](examples/)).
2. Register the hook with the agent you're using. `toolgate init` outputs the configuration snippet:

```console
$ toolgate init --agent claude-code   # for ~/.claude/settings.json
$ toolgate init --agent copilot       # for ~/.copilot/hooks/toolgate.json
$ toolgate init --agent cursor        # for ~/.cursor/hooks.json (with failClosed: true)
```

3. Check the registration status and policy health:

```console
$ toolgate doctor
```

## Policy

Rules are written against capability (`kind`), evaluated top to bottom, and the first match wins (first-match-wins). If nothing matches, `default` applies.

```yaml
version: 1
default: ask

include:
  - defaults:recommended # use built-in preset

rules:
  # Catch rm -rf on any agent, based on AST
  - name: block-rm-recursive-force
    action: deny
    when: |
      kind == "exec" &&
      cmds.exists(c,
        c.name == "rm" &&
        c.flags.exists(f, f == "r" || f == "recursive") &&
        c.flags.exists(f, f == "f" || f == "force"))
    message: "rm -rf is blocked (matched by AST, not text)."
```

### Include system and built-in policies

Policies can include other policies via `include:`. Built-in presets are referenced with the `defaults:` prefix:

```yaml
include:
  - defaults:recommended # all standard protections combined
  - defaults:self-protection # block writes to toolgate/agent configs
  - defaults:deny-publish # block npm publish, cargo publish, etc.
  - defaults:deny-deploy # block deploy commands
  - defaults:dangerous-commands # ask for rm -rf, find -exec, etc.
  - defaults:git # ask for force push, history rewrite, reset --hard, etc.
  - defaults:safe-cwd # allow ops in cwd, ask outside
  - defaults:sensitive-file-access # control access to .env
  - defaults:allow-claude-code # allow ~/.claude access and harmless tools
```

`defaults:recommended` combines all the above for a practical starting point. See [examples/default.yaml](examples/default.yaml).

### Reusable expressions with `lets`

Define reusable CEL expressions with `lets:` to keep rules DRY:

```yaml
lets:
  safe_cmds: '["ls", "cat", "grep", "head", "tail"]'
  dangerous_flags: 'c.flags.exists(f, f == "f" || f == "force")'

rules:
  - name: allow-safe-readonly
    action: allow
    when: kind == "exec" && cmds.all(c, c.name in safe_cmds)

  - name: ask-forced-commands
    action: ask
    when: kind == "exec" && cmds.exists(c, dangerous_flags)
```

### `kind`: capabilities and how agent events map to them

Every rule matches on `kind`, the normalized capability a tool call exercises — never on agent-specific tool names. Each agent's native tools/events are translated into one of these:

| `kind`        | Meaning                         | Claude Code tool                             | Copilot tool                                                                                  | Cursor hook event            |
| ------------- | ------------------------------- | -------------------------------------------- | --------------------------------------------------------------------------------------------- | ---------------------------- |
| `exec`        | Shell command execution         | `Bash`                                       | `bash`, `shell`, `run`, `run_in_terminal`, `execute`                                          | `beforeShellExecution`       |
| `file.read`   | Reading a file                  | `Read`                                       | `read`, `read_file`, `view`, `cat`                                                            | `beforeReadFile`             |
| `file.write`  | Creating, editing or deleting   | `Write`, `Edit`, `MultiEdit`, `NotebookEdit` | `write`, `create`, `create_file`, `edit`, `edit_file`, `str_replace`, `apply_patch`, `delete` | _(none — no pre-write hook)_ |
| `file.search` | Searching files                 | `Grep`, `Glob`                               | _(none)_                                                                                      | _(none)_                     |
| `mcp`         | MCP tool invocation             | `mcp__<server>__<tool>`                      | `mcp__<server>__<tool>`                                                                       | `beforeMCPExecution`         |
| `other`       | Anything else (default applies) | any unrecognized tool                        | any unrecognized tool                                                                         | any other event              |

Notes:

- Cursor has **no pre-write hook**, so `file.write` never fires for Cursor (see [§What It Can and Cannot Prevent](#what-it-can-and-cannot-prevent)). Cursor also does not emit a file-search event.
- Anything toolgate can't classify becomes `other` rather than being dropped, so the `default` action still applies. Use `kind.startsWith("file.")` to match reads, writes and searches at once.

### Available variables

These top-level variables are bound for every rule:

| Variable     | Type           | Description                                                                  |
| ------------ | -------------- | ---------------------------------------------------------------------------- |
| `kind`       | string         | Normalized capability (see table above).                                     |
| `agent`      | string         | `claude-code` / `copilot` / `cursor`. For agent-specific rules.              |
| `tool`       | string         | The agent-native tool name (e.g. `Bash`, `Read`). Escape hatch.              |
| `cmd`        | string         | Raw shell command string. Empty unless `kind == "exec"`.                     |
| `cmds`       | list           | Parsed command invocations from the shell AST (see next table). `exec` only. |
| `paths`      | list\<string\> | Absolute, normalized paths the call touches (file.\* events).                |
| `path`       | string         | First element of `paths` (`""` if none). Convenience for single-path calls.  |
| `reads`      | list\<string\> | Paths being read (file.read, or from cmds for exec).                         |
| `writes`     | list\<string\> | Paths being written (file.write, or from cmds for exec).                     |
| `accesses`   | list\<string\> | Union of all paths accessed (reads + writes + paths).                        |
| `mcp`        | map            | `mcp.server` / `mcp.tool` for `kind == "mcp"`.                               |
| `cwd`        | string         | Working directory of the tool call.                                          |
| `home`       | string         | The user's home directory (`""` if unknown). Use to write portable rules.    |
| `session_id` | string         | Agent session/conversation id (`""` if not provided).                        |
| `input`      | map            | Raw, agent-native tool input.                                                |
| `parse_ok`   | bool           | Whether the shell command parsed cleanly (`exec` only).                      |

String helpers from CEL's `ext.Strings` are available (`startsWith`, `endsWith`, `contains`,
`matches`, etc.). `matches` takes a regular expression, as used with the `r'...'` raw-string
literals in the examples.

### Custom CEL functions

Path strings support these helper methods:

| Function       | Description                                                                                                                                            |
| -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `p.glob(pat)`  | True if path matches the glob pattern. Patterns without `/` are prefixed with `**/` (match at any depth). Supports brace expansion: `"{.env,.env.*}"`. |
| `p.under(dir)` | True if path equals `dir` or is under it. Empty `dir` always returns false.                                                                            |
| `p.in_tmp()`   | True if path is under `/tmp`, `/var/tmp`, `/private/tmp`, or `/private/var/folders`.                                                                   |

Examples:

```yaml
# Block access to sensitive dotfiles anywhere in the tree
- name: block-env-files
  action: deny
  when: |
    writes.exists(p, p.glob("{.env,.env.*,.env.local}"))

# Allow writes only under cwd
- name: allow-cwd-writes
  action: allow
  when: |
    kind == "file.write" && paths.all(p, p.under(cwd))

# Allow tmp file operations
- name: allow-tmp
  action: allow
  when: |
    kind.startsWith("file.") && paths.all(p, p.in_tmp())
```

### The `cmds` command object

For `exec` events the shell command is parsed into an **AST** and flattened into a list of individual command invocations — `A && B`, pipelines, subshells and command substitutions all become separate entries, so rules judge structure rather than matching text. Each element of `cmds` has these fields:

| Field         | Type           | Description                                                                                                                                                                                                            |
| ------------- | -------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `name`        | string         | Resolved executable name (`""` if unknown). Wrappers like `sudo`/`env`/`xargs`/`timeout` are unwrapped so `sudo rm` reports `name == "rm"`.                                                                            |
| `args`        | list\<string\> | Arguments with quotes removed (best-effort).                                                                                                                                                                           |
| `flags`       | list\<string\> | Normalized flag set: `-rf` → `["r","f"]`, `--force` → `["force"]`.                                                                                                                                                     |
| `writes_to`   | list\<string\> | Absolute paths the command may write to, inferred from its arguments (`rm`, `cp`/`mv` destination, `tee`, `dd of=`, `sed -i`, redirections, …).                                                                        |
| `reads_from`  | list\<string\> | Absolute paths the command may read from (`cat`, `grep` targets, `dd if=`, …).                                                                                                                                         |
| `in_pipe`     | bool           | True if this command is part of a pipeline (`… \| this \| …`).                                                                                                                                                         |
| `pipe_from`   | list\<string\> | Names of all upstream commands in the same pipeline. E.g. for `curl … \| sh`, the `sh` command has `pipe_from` containing `"curl"`.                                                                                    |
| `has_unknown` | bool           | True when the command's name or arguments contain an unresolved expansion (a variable, `$(...)`, glob, etc.) that could not be statically resolved. Use it to be cautious about commands whose real target is unknown. |
| `redirects`   | list           | Redirections on the statement; each has `.op` (`">"`, `">>"`, `"<"`, …) and `.target` (literal target, `""` if unresolvable).                                                                                          |
| `raw`         | string         | Original text of this invocation.                                                                                                                                                                                      |

Because a command line yields many entries, rules typically use `cmds.exists(c, …)`:

```yaml
# Block `curl … | sh`: a shell reading from an upstream downloader in the same pipeline.
- name: block-download-pipe-shell
  action: deny
  when: |
    kind == "exec" &&
    cmds.exists(c,
      c.name in ["sh","bash","zsh","dash"] &&
      c.in_pipe &&
      c.pipe_from.exists(p, p in ["curl","wget","fetch"]))
  message: "curl/wget piped into a shell is blocked."

# Ask before a destructive command whose target can't be resolved statically.
- name: ask-destructive-with-unknown
  action: ask
  when: |
    kind == "exec" &&
    cmds.exists(c, c.has_unknown && c.name in ["rm","dd","mkfs","shred"])
  message: "Destructive command with unresolved expansion. Confirm."
```

`paths` (and the per-command `writes_to` / `reads_from`) is already normalized to absolute paths, so rules targeting paths under the home directory should not hard-code the username; instead, concatenate with `home` (which resolves to each user's home directory at evaluation time).
This lets a shared team policy or a project's `.toolgate.yaml` work unchanged on a different machine:

```yaml
- name: protect-home-credentials
  action: deny
  when: |
    kind.startsWith("file.") && home != "" &&
    paths.exists(p, p.startsWith(home + "/.ssh/") ||
                    p.startsWith(home + "/.aws/"))
  message: "Access to home credentials is blocked."
```

Ready-to-use samples are available in [examples/](examples/).

Project policies (`.toolgate.yaml`) can tighten the default action but not loosen it beyond the user policy's default.

## Self-Protection

Denying writes to toolgate's own policy or to each agent's hook configuration closes off the path by which an agent could disable the gate via a tool call.
This is a **regular policy, not a built-in rule**, so users can decide whether they need it.

## What It Can and Cannot Prevent

toolgate only affects tool calls that go through a hook. The scope of what can be gated differs by agent.

| Gate target                        | Claude Code | Copilot | Cursor                          |
| ---------------------------------- | ----------- | ------- | ------------------------------- |
| Shell execution (before execution) | ○           | ○       | ○                               |
| File read (before execution)       | ○           | ○       | ○                               |
| File write (before execution)      | ○           | ○       | **×** (no pre-execution hook)   |
| MCP tool call (before execution)   | ○           | ○       | ○                               |
| fail-closed on hook failure        | △           | △       | △ (must set `failClosed: true`) |

- **Can prevent**: accidents by a agent (`rm -rf`, secret files, `curl | sh`, etc.), gate loosening via a malicious repository, and tampering with the gate via tool calls (when [self-protection](#self-protection) rules are in place).
- **Partial**: evasion by an adversarial agent (encoding, `python -c`, `eval`) can at best be downgraded to ask. **Child processes of an allowed process (e.g., postinstall) are invisible.**
- **Cannot prevent**: operations for which the hook doesn't fire, **Cursor file writes**, host-side fail-open, TOCTOU. Ensure these are covered by combining toolgate with containers and privilege separation.

## CLI

```console
# Run as a hook (reads stdin, writes decision to stdout)
$ toolgate hook <agent>

# Print hook configuration snippet for an agent
$ toolgate init --agent <agent>

# Check hook registration and policy health
$ toolgate doctor
```

### `toolgate hook`

The main command used as a pre-tool-use hook. Reads JSON from stdin, evaluates the policy, and writes the decision to stdout.

```console
$ echo '{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}' | toolgate hook claude-code | jq
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "ask",
    "permissionDecisionReason": "rm -rf detected. Confirm."
  }
}
```

### `toolgate init`

Prints the configuration snippet to register toolgate with an agent:

```console
$ toolgate init --agent claude-code   # for ~/.claude/settings.json
$ toolgate init --agent copilot       # for ~/.copilot/hooks/toolgate.json
$ toolgate init --agent cursor        # for ~/.cursor/hooks.json
```

### `toolgate doctor`

Checks that hooks are properly registered and policies are valid:

```console
$ toolgate doctor
ok:    user policy ~/.config/toolgate/policy.yaml compiles (12 rules, default ask)
ok:    ~/.claude/settings.json registers toolgate
warn:  no hook config at ~/.copilot/hooks/toolgate.json (toolgate not registered there)
```

## Environment Variables

| Variable               | Effect                                                                                                   |
| ---------------------- | -------------------------------------------------------------------------------------------------------- |
| `TOOLGATE_LOG=<path>`  | Append decision logs in JSON Lines format                                                                |
| `TOOLGATE_DRY_RUN=1`   | Always returns allow while logging what the actual decision would have been (for trial runs of a policy) |
| `TOOLGATE_FAIL_OPEN=1` | Falls back to allow on internal errors (**not recommended** — reduces safety)                            |
