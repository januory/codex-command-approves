# command-approves

`command-approves` is a Codex hook that applies an ordered command policy before
shell tools run. It replaces a Git-push-specific guard with general rules read
from:

```text
C:\Users\Administrator\.codex\command-approves\rules.json
```

The policy is read again for every command, so edits take effect on the next
tool call without restarting Codex.

Copy this repository to `C:\Users\Administrator\.codex\command-approves` or keep
the path in `hooks.json` pointed at wherever `command-approves.js` is installed.

## Rules

```json
{
  "rules": [
    { "pattern": "git status", "action": "allow" },
    { "pattern": "git push", "action": "deny" },
    { "pattern": "git", "action": "ask" }
  ]
}
```

- Rules are evaluated in file order. The first rule that matches one command
  decides that command.
- A script can contain several commands. The strictest result across all of
  them wins: `deny` over `ask` over `allow`.
- Patterns are token-prefix matches after normalization. `git push` matches
  `git push --force` and `git -C repo push`, but not `git pull`.
- Supported actions are `allow`, `ask`, and `deny`. Compatibility aliases are
  `approve`/`permit`, `prompt`, and `block`/`reject`.
- A rule can include `reason` to customize the denial shown to the model.
- Invalid or unreadable `rules.json` fails closed for shell commands.

## Codex events

The hook is registered for both `PreToolUse` and `PermissionRequest` with a
`Bash` matcher.

- `deny` is returned as an explicit Codex denial and the command does not run.
- `allow` delegates in `PreToolUse`; if Codex asks for permission, the hook
  approves that request.
- `ask` opens a Windows confirmation dialog showing the command, matched rule,
  and working directory. Choosing Yes allows the command; choosing No, closing
  the dialog, or timing out denies it.

Codex does not support `permissionDecision: "ask"` in `PreToolUse` today, so the
confirmation dialog is displayed by the hook process itself. It works even when
the active approval policy is `never`. On non-Windows platforms, `ask` fails
closed because no native dialog is available.

Dialog copy is localized to Chinese or English. `COMMAND_APPROVES_LOCALE` takes
priority when set; otherwise the hook uses `LC_ALL`, `LC_MESSAGES`, `LANG`, or
the system locale. Locales beginning with `zh` use Chinese and all other
locales use English.

The installed hook should allow enough time for the dialog. The default internal
timeout is 8 seconds for backwards safety. For normal use, set a longer internal
timeout and keep the Codex hook timeout above it:

```json
{
  "type": "command",
  "command": "node \"C:\\Users\\Administrator\\.codex\\command-approves\\command-approves.js\" --dialog-timeout-ms=110000",
  "timeout": 120
}
```

The dialog timeout must remain below the Codex hook timeout. If Codex kills the
hook process first, the hook cannot return its fail-closed denial.

## Test

```powershell
cd C:\Users\Administrator\.codex\command-approves
npm test
```

After changing the hook registration, review it in `/hooks` and trust the new
definition if Codex requests it. Hooks added to an already-running session
usually become available in a new session.
