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
- `ask` declines to decide in `PreToolUse` and `PermissionRequest`, preserving
  Codex's native approval prompt.

Codex does not support `permissionDecision: "ask"` in `PreToolUse` today. As a
result, an `ask` rule can retain the native prompt but cannot force a prompt for
a command that the active sandbox and approval policy allow without asking.

## Test

```powershell
cd C:\Users\Administrator\.codex\command-approves
npm test
```

After changing the hook registration, review it in `/hooks` and trust the new
definition if Codex requests it. Hooks added to an already-running session
usually become available in a new session.
