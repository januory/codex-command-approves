'use strict';

const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const hook = path.join(__dirname, '..', 'command-approves.js');

function run(event, rules) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'command-approves-test-'));
  const rulesPath = path.join(root, 'rules.json');
  fs.writeFileSync(rulesPath, typeof rules === 'string' ? rules : JSON.stringify({ rules }), 'utf8');
  try {
    const result = spawnSync(process.execPath, [hook], {
      input: JSON.stringify(event),
      encoding: 'utf8',
      timeout: 10000,
      env: {
        ...process.env,
        COMMAND_APPROVES_RULES: rulesPath,
      },
    });
    assert.equal(result.error, undefined);
    assert.equal(result.status, 0, result.stderr);
    return {
      stderr: result.stderr,
      output: result.stdout.trim() === '' ? undefined : JSON.parse(result.stdout),
    };
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

function bash(command, eventName = 'PreToolUse') {
  return {
    cwd: 'C:\\workspace',
    hook_event_name: eventName,
    permission_mode: 'default',
    tool_input: { command },
    tool_name: 'Bash',
  };
}

test('PreToolUse denies a matching command', () => {
  const { output } = run(bash('git push origin main'), [
    { pattern: 'git push', action: 'deny' },
  ]);

  assert.equal(output.hookSpecificOutput.hookEventName, 'PreToolUse');
  assert.equal(output.hookSpecificOutput.permissionDecision, 'deny');
  assert.match(output.hookSpecificOutput.permissionDecisionReason, /git push/);
  assert.match(output.hookSpecificOutput.permissionDecisionReason, /git push origin main/);
});

test('PermissionRequest denies a matching deny rule', () => {
  const { output } = run(bash('git push', 'PermissionRequest'), [
    { pattern: 'git push', action: 'deny' },
  ]);

  assert.equal(output.hookSpecificOutput.hookEventName, 'PermissionRequest');
  assert.deepEqual(output.hookSpecificOutput.decision.behavior, 'deny');
  assert.match(output.hookSpecificOutput.decision.message, /git push/);
});

test('an ask rule defers to the normal approval flow in both events', () => {
  for (const eventName of ['PreToolUse', 'PermissionRequest']) {
    const { output } = run(bash('p4 submit', eventName), [
      { pattern: 'p4', action: 'ask' },
    ]);
    assert.equal(output, undefined, eventName);
  }
});

test('an allow rule passes PreToolUse without overriding later safety layers', () => {
  const { output } = run(bash('git status'), [
    { pattern: 'git status', action: 'allow' },
  ]);
  assert.equal(output, undefined);
});

test('an allow rule approves a PermissionRequest it matched', () => {
  const { output } = run(bash('git status', 'PermissionRequest'), [
    { pattern: 'git status', action: 'allow' },
  ]);

  assert.equal(output.hookSpecificOutput.hookEventName, 'PermissionRequest');
  assert.deepEqual(output.hookSpecificOutput.decision, { behavior: 'allow' });
});

test('the first matching rule decides, so an allow exception precedes a deny', () => {
  const rules = [
    { pattern: 'git push origin preview', action: 'allow' },
    { pattern: 'git push', action: 'deny' },
  ];

  assert.equal(run(bash('git push origin preview'), rules).output, undefined);
  assert.equal(
    run(bash('git push origin main')).output.hookSpecificOutput.permissionDecision,
    'deny',
  );
});

test('the strictest result across a command chain wins', () => {
  const { output } = run(bash('git status && git push --force'), [
    { pattern: 'git status', action: 'allow' },
    { pattern: 'git push', action: 'deny' },
  ]);

  assert.equal(output.hookSpecificOutput.permissionDecision, 'deny');
});

test('git global options, executable paths, wrappers, and nested shells are normalized', () => {
  const commands = [
    'git -C repo push',
    '"C:\\Program Files\\Git\\cmd\\git.exe" push',
    'GIT_TRACE=1 git push',
    'timeout 20 git push',
    'bash -c "git push"',
    'pwsh -Command "git push"',
    'cmd /c "git push"',
    'echo $(git push)',
  ];

  for (const command of commands) {
    const { output } = run(bash(command), [
      { pattern: 'git push', action: 'deny' },
    ]);
    assert.equal(output?.hookSpecificOutput?.permissionDecision, 'deny', command);
  }
});

test('quoted text and command prefixes do not create false positives', () => {
  for (const command of ['echo "git push"', 'git pull', 'git pushd', 'git log --grep="git push"']) {
    const { output } = run(bash(command), [
      { pattern: 'git push', action: 'deny' },
    ]);
    assert.equal(output, undefined, command);
  }
});

test('tool calls without a shell command are ignored', () => {
  const event = {
    hook_event_name: 'PreToolUse',
    tool_input: { path: 'git push' },
    tool_name: 'apply_patch',
  };
  const { output } = run(event, [{ pattern: 'git push', action: 'deny' }]);
  assert.equal(output, undefined);
});

test('an unreadable policy fails closed', () => {
  const { output } = run(bash('git status'), '{ broken json');

  assert.equal(output.hookSpecificOutput.hookEventName, 'PreToolUse');
  assert.equal(output.hookSpecificOutput.permissionDecision, 'deny');
  assert.match(output.hookSpecificOutput.permissionDecisionReason, /rules\.json/);
});

test('block aliases are normalized to deny', () => {
  const { output } = run(bash('rm -rf build'), [
    { pattern: 'rm -rf', action: 'block' },
  ]);

  assert.equal(output.hookSpecificOutput.permissionDecision, 'deny');
});
