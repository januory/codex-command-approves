#!/usr/bin/env node
'use strict';

const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const RULES_PATH = process.env.COMMAND_APPROVES_RULES || path.join(__dirname, 'rules.json');
const MAX_INPUT_LENGTH = 1024 * 1024;
const MAX_DEPTH = 8;
const DEFAULT_ASK_DIALOG_TIMEOUT_MS = 8000;
const DIALOG_TIMEOUT_ARG = '--dialog-timeout-ms=';
const ASK_DIALOG_COPY = {
  en: {
    title: 'Codex command approval',
    prompt: 'Allow this command?',
    command: 'Command: ',
    rule: 'Matched rule: ',
    cwd: 'Working directory: ',
    decision: 'Choose Yes to run this command. Choose No to deny it.',
  },
  zh: {
    title: 'Codex 命令审批',
    prompt: '允许执行此命令吗？',
    command: '命令：',
    rule: '匹配规则：',
    cwd: '工作目录：',
    decision: '选择“是”执行命令，选择“否”拒绝执行。',
  },
};
const POSIX = 'posix';
const POWERSHELL = 'powershell';
const ACTION_RANK = { allow: 0, ask: 1, deny: 2 };
const ACTION_ALIASES = new Map([
  ['allow', 'allow'],
  ['approve', 'allow'],
  ['permit', 'allow'],
  ['ask', 'ask'],
  ['prompt', 'ask'],
  ['deny', 'deny'],
  ['block', 'deny'],
  ['reject', 'deny'],
]);
const EXECUTABLE_EXTENSIONS = ['.exe', '.cmd', '.bat', '.ps1', '.com', '.sh'];
const ENV_ASSIGNMENT = /^(?:\$env:)?[A-Za-z_][A-Za-z0-9_]*=/i;
const GIT_GLOBAL_FLAGS_WITH_VALUE = new Set([
  '-C',
  '-c',
  '--git-dir',
  '--work-tree',
  '--namespace',
  '--config-env',
  '--super-prefix',
  '--exec-path',
  '--attr-source',
]);
const WRAPPERS = new Map([
  ['sudo', { valued: 'ugCprtTUhDRg', positional: 0 }],
  ['doas', { valued: 'uC', positional: 0 }],
  ['env', { valued: 'uCSP', positional: 0 }],
  ['xargs', { valued: 'nILPsdaE', positional: 0 }],
  ['nice', { valued: 'n', positional: 0 }],
  ['timeout', { valued: 'sk', positional: 1 }],
  ['command', { valued: '', positional: 0 }],
  ['exec', { valued: 'a', positional: 0 }],
  ['builtin', { valued: '', positional: 0 }],
  ['nohup', { valued: '', positional: 0 }],
  ['time', { valued: 'of', positional: 0 }],
  ['setsid', { valued: '', positional: 0 }],
  ['stdbuf', { valued: 'ioe', positional: 0 }],
  ['ssh', { valued: 'bcDEeFIiJLlmOopQRSWw', positional: 1 }],
  ['wsl', { valued: 'd', positional: 0 }],
]);
const NESTED_SHELLS = new Map([
  ['sh', ['-c']],
  ['bash', ['-c']],
  ['zsh', ['-c']],
  ['dash', ['-c']],
  ['ksh', ['-c']],
  ['fish', ['-c']],
  ['pwsh', ['-c', '-command']],
  ['powershell', ['-c', '-command']],
  ['cmd', ['/c', '/k']],
]);
const POWERSHELL_ESCAPES = new Set(['`', '"', "'", '$', 'a', 'b', 'e', 'f', 'n', 'r', 't', 'v', 'u', '0']);

function readSubstitution(text, start) {
  let depth = 0;
  let index = start + 1;
  while (index < text.length) {
    const char = text[index];
    if (char === "'") {
      const close = text.indexOf("'", index + 1);
      if (close < 0) return undefined;
      index = close + 1;
      continue;
    }
    if (char === '"') {
      let cursor = index + 1;
      let closed = false;
      while (cursor < text.length) {
        if (text[cursor] === '\\' && cursor + 1 < text.length) {
          cursor += 2;
          continue;
        }
        if (text[cursor] === '"') {
          closed = true;
          cursor += 1;
          break;
        }
        cursor += 1;
      }
      if (!closed) return undefined;
      index = cursor;
      continue;
    }
    if (char === '(') {
      depth += 1;
    } else if (char === ')') {
      depth -= 1;
      if (depth === 0) {
        return {
          text: text.slice(start, index + 1),
          inner: text.slice(start + 2, index),
          end: index + 1,
        };
      }
    }
    index += 1;
  }
  return undefined;
}

function readBacktickRun(text, start) {
  const close = text.indexOf('`', start + 1);
  if (close < 0) return undefined;
  return {
    text: text.slice(start, close + 1),
    inner: text.slice(start + 1, close),
    end: close + 1,
  };
}

function tokenizeScript(text, mode = POSIX) {
  const segments = [];
  const substitutions = [];
  let tokens = [];
  let word = '';
  let wordQuoted = false;
  let opaque = false;

  const pushWord = () => {
    if (word !== '' || wordQuoted) tokens.push(word);
    word = '';
    wordQuoted = false;
  };
  const endSegment = () => {
    pushWord();
    if (tokens.length > 0) segments.push(tokens);
    tokens = [];
  };
  const consumeSubstitution = (index) => {
    const substitution = readSubstitution(text, index);
    if (substitution === undefined) {
      opaque = true;
      word += text[index];
      return index + 1;
    }
    substitutions.push(substitution.inner);
    word += substitution.text;
    wordQuoted = true;
    return substitution.end;
  };
  const consumeBacktick = (index) => {
    if (mode === POWERSHELL) {
      const next = text[index + 1];
      if (next === undefined) return index + 1;
      if (POWERSHELL_ESCAPES.has(next)) {
        word += next;
        return index + 2;
      }
      opaque = true;
      word += next;
      return index + 2;
    }
    const run = readBacktickRun(text, index);
    if (run === undefined) {
      opaque = true;
      word += text[index];
      return index + 1;
    }
    substitutions.push(run.inner);
    word += run.text;
    wordQuoted = true;
    return run.end;
  };

  let index = 0;
  while (index < text.length) {
    const char = text[index];

    if (char === '\\' && mode === POSIX) {
      const next = text[index + 1];
      if (next === '\n') {
        index += 2;
        continue;
      }
      if (next !== undefined) {
        word += next;
        wordQuoted = true;
        index += 2;
        continue;
      }
      word += char;
      index += 1;
      continue;
    }

    if (char === "'") {
      let cursor = index + 1;
      let buffer = '';
      let closed = false;
      while (cursor < text.length) {
        const inner = text[cursor];
        if (inner === "'" && mode === POWERSHELL && text[cursor + 1] === "'") {
          buffer += "'";
          cursor += 2;
          continue;
        }
        if (inner === "'") {
          closed = true;
          cursor += 1;
          break;
        }
        buffer += inner;
        cursor += 1;
      }
      if (!closed) opaque = true;
      word += buffer;
      wordQuoted = true;
      index = cursor;
      continue;
    }

    if (char === '"') {
      let cursor = index + 1;
      let buffer = '';
      let closed = false;
      while (cursor < text.length) {
        const inner = text[cursor];
        if (inner === '\\' && mode === POSIX && cursor + 1 < text.length) {
          const next = text[cursor + 1];
          buffer += '"\\`$'.includes(next) ? next : inner + next;
          cursor += 2;
          continue;
        }
        if (inner === '"') {
          closed = true;
          cursor += 1;
          break;
        }
        if (inner === '`' && mode === POWERSHELL) {
          const next = text[cursor + 1];
          if (next !== undefined && POWERSHELL_ESCAPES.has(next)) {
            buffer += next;
            cursor += 2;
            continue;
          }
          opaque = true;
          cursor += next === undefined ? 1 : 2;
          continue;
        }
        if (inner === '$' && text[cursor + 1] === '(') {
          const substitution = readSubstitution(text, cursor);
          if (substitution === undefined) {
            opaque = true;
            buffer += inner;
            cursor += 1;
            continue;
          }
          substitutions.push(substitution.inner);
          buffer += substitution.text;
          cursor = substitution.end;
          continue;
        }
        if (inner === '`' && mode === POSIX) {
          const run = readBacktickRun(text, cursor);
          if (run === undefined) {
            opaque = true;
            buffer += inner;
            cursor += 1;
            continue;
          }
          substitutions.push(run.inner);
          buffer += run.text;
          cursor = run.end;
          continue;
        }
        buffer += inner;
        cursor += 1;
      }
      if (!closed) opaque = true;
      word += buffer;
      wordQuoted = true;
      index = cursor;
      continue;
    }

    if (char === '$' && text[index + 1] === '(') {
      index = consumeSubstitution(index);
      continue;
    }

    if (char === '`') {
      index = consumeBacktick(index);
      continue;
    }

    if ((char === '>' || char === '<' || /[0-9]/.test(char)) && word === '') {
      const redirection = /^(?:[0-9]*[<>]{1,2}&?[0-9]*|&>>?)/.exec(text.slice(index));
      if (redirection !== null && redirection[0] !== '') {
        tokens.push(redirection[0]);
        index += redirection[0].length;
        continue;
      }
    }

    if (char === '#' && word === '' && !wordQuoted) {
      const newline = text.indexOf('\n', index);
      index = newline < 0 ? text.length : newline;
      continue;
    }

    if (char === '\n' || char === ';') {
      endSegment();
      index += 1;
      continue;
    }

    if (char === '&') {
      endSegment();
      index += text[index + 1] === '&' ? 2 : 1;
      continue;
    }

    if (char === '|') {
      endSegment();
      index += text[index + 1] === '|' ? 2 : 1;
      continue;
    }

    if (char === '(' || char === ')' || char === '{' || char === '}') {
      pushWord();
      index += 1;
      continue;
    }

    if (/\s/.test(char)) {
      pushWord();
      index += 1;
      continue;
    }

    word += char;
    index += 1;
  }

  endSegment();
  return { segments, substitutions, opaque };
}

function programName(word) {
  const base = String(word).replace(/^.*[\\/]/, '');
  const lower = base.toLowerCase();
  for (const extension of EXECUTABLE_EXTENSIONS) {
    if (lower.endsWith(extension) && lower.length > extension.length) {
      return lower.slice(0, -extension.length);
    }
  }
  return lower;
}

function skipWrapperOptions(spec, tokens) {
  let index = 1;
  let positional = 0;
  while (index < tokens.length) {
    const word = tokens[index];
    if (ENV_ASSIGNMENT.test(word)) {
      index += 1;
      continue;
    }
    if (!word.startsWith('-') && positional < spec.positional) {
      positional += 1;
      index += 1;
      continue;
    }
    if (word.startsWith('-') && word !== '-') {
      const short = /^-([A-Za-z])(.*)$/.exec(word);
      if (short !== null && spec.valued.includes(short[1])) {
        index += short[2] === '' ? 2 : 1;
        continue;
      }
      index += 1;
      continue;
    }
    return index;
  }
  return index;
}

function stripGitGlobals(words) {
  let index = 1;
  while (index < words.length) {
    const word = words[index];
    const flag = word.includes('=') ? word.slice(0, word.indexOf('=')) : word;
    if (GIT_GLOBAL_FLAGS_WITH_VALUE.has(flag)) {
      index += flag === word ? 2 : 1;
      continue;
    }
    if (word.startsWith('-')) {
      index += 1;
      continue;
    }
    break;
  }
  return [words[0], ...words.slice(index)];
}

function analyzeCommand(command, options = {}) {
  const found = new Map();
  const nested = [];
  let opaque = false;

  const record = (words, text, origin) => {
    const key = words.join(' ');
    if (!found.has(key)) found.set(key, { words, text, origin });
  };

  const visit = (raw, depth, mode) => {
    let start = 0;
    while (start < raw.length && ENV_ASSIGNMENT.test(raw[start])) start += 1;
    if (start >= raw.length) return;
    raw = raw.slice(start);

    const name = programName(raw[0]);
    const shellFlags = NESTED_SHELLS.get(name);
    if (shellFlags !== undefined) {
      let flagIndex = raw.findIndex((token) => shellFlags.includes(token.toLowerCase()));
      if (flagIndex < 0 && !['pwsh', 'powershell', 'cmd'].includes(name)) {
        flagIndex = raw.findIndex((token) => /^-[a-z]*c[a-z]*$/i.test(token));
      }
      if (flagIndex >= 0 && raw[flagIndex + 1] !== undefined) {
        const script = raw.slice(flagIndex + 1).join(' ');
        nested.push(script);
        walk(script, mode, depth + 1);
        return;
      }
      record([name], raw.join(' '), mode);
      return;
    }

    if (name === 'eval' && raw.length > 1) {
      const script = raw.slice(1).join(' ');
      nested.push(script);
      walk(script, mode, depth + 1);
      return;
    }

    const wrapper = WRAPPERS.get(name);
    if (wrapper !== undefined) {
      const inner = raw.slice(skipWrapperOptions(wrapper, raw.map((token) => token.toLowerCase())));
      if (inner.length === 0) {
        record([name], raw.join(' '), mode);
        return;
      }
      if (inner.length === 1 && /\s/.test(inner[0])) {
        nested.push(inner[0]);
        walk(inner[0], mode, depth + 1);
        return;
      }
      visit(inner, depth + 1, mode);
      return;
    }

    const words = [name, ...raw.slice(1).map((token) => token.toLowerCase())];
    record(name === 'git' ? stripGitGlobals(words) : words, raw.join(' '), mode);
  };

  const walk = (script, mode, depth) => {
    if (depth > MAX_DEPTH) {
      opaque = true;
      return;
    }
    const parsed = tokenizeScript(script, mode);
    if (parsed.opaque) opaque = true;
    for (const substitution of parsed.substitutions) {
      nested.push(substitution);
      walk(substitution, mode, depth + 1);
    }
    for (const tokens of parsed.segments) visit(tokens, depth, mode);
  };

  const modes = options.mode === undefined ? [POSIX, POWERSHELL] : [options.mode];
  for (const mode of modes) walk(command, mode, 0);
  return { invocations: [...found.values()], nested, opaque };
}

function matchesRule(ruleWords, words) {
  if (ruleWords.length === 0 || ruleWords.length > words.length) return false;
  for (let index = 0; index < ruleWords.length; index += 1) {
    if (ruleWords[index] !== words[index]) return false;
  }
  return true;
}

function normalizeExpression(expression, mode = POSIX) {
  const parsed = tokenizeScript(expression, mode);
  const first = parsed.segments[0] || [];
  if (first.length === 0) return [];
  let start = 0;
  while (start < first.length && ENV_ASSIGNMENT.test(first[start])) start += 1;
  if (start >= first.length) return [];
  const trimmed = first.slice(start);
  const name = programName(trimmed[0]);
  const normalized = [name, ...trimmed.slice(1).map((token) => token.toLowerCase())];
  return name === 'git' ? stripGitGlobals(normalized) : normalized;
}

function normalizeRules(source) {
  if (!Array.isArray(source)) {
    throw new Error('expected a top-level "rules" array');
  }

  const rules = [];
  const invalid = [];
  for (let index = 0; index < source.length; index += 1) {
    const entry = source[index] && typeof source[index] === 'object' ? source[index] : {};
    const pattern = typeof entry.pattern === 'string' ? entry.pattern.trim() : '';
    const words = pattern === '' ? [] : normalizeExpression(pattern);
    if (words.length === 0) {
      invalid.push(index);
      continue;
    }
    const requestedAction = typeof entry.action === 'string' ? entry.action.trim().toLowerCase() : 'deny';
    const action = ACTION_ALIASES.get(requestedAction) || 'deny';
    const reason = typeof entry.reason === 'string' && entry.reason.trim() !== ''
      ? entry.reason.trim()
      : undefined;
    rules.push({ action, index, pattern, reason, words });
  }
  return { invalid, rules };
}

function loadRules(rulesPath = process.env.COMMAND_APPROVES_RULES || RULES_PATH) {
  const text = fs.readFileSync(rulesPath, 'utf8');
  const document = JSON.parse(text);
  const source = Array.isArray(document) ? document : document && document.rules;
  return normalizeRules(source).rules;
}

function evaluateCommand(command, rules) {
  const analysis = analyzeCommand(command);
  let outcome;
  for (const invocation of analysis.invocations) {
    const rule = rules.find((candidate) => matchesRule(candidate.words, invocation.words));
    if (rule === undefined) continue;
    if (outcome === undefined || ACTION_RANK[rule.action] > ACTION_RANK[outcome.action]) {
      outcome = rule;
    }
    if (outcome.action === 'deny') break;
  }
  return {
    action: outcome ? outcome.action : 'none',
    analysis,
    rule: outcome,
  };
}

function commandOf(toolInput) {
  if (typeof toolInput === 'string') return toolInput.trim() === '' ? undefined : toolInput;
  if (toolInput === null || typeof toolInput !== 'object' || Array.isArray(toolInput)) return undefined;
  const value = toolInput.command;
  return typeof value === 'string' && value.trim() !== '' ? value : undefined;
}

function eventNameOf(event) {
  const name = String(event.hook_event_name || '').toLowerCase();
  if (name === 'pretooluse') return 'PreToolUse';
  if (name === 'permissionrequest') return 'PermissionRequest';
  return undefined;
}

function denyReason(command, rule) {
  if (rule && rule.reason) {
    return `${rule.reason} Matched rule "${rule.pattern}". The command was: ${command}`;
  }
  const pattern = rule ? `"${rule.pattern}"` : 'the configured command policy';
  return `Command denied by command-approves rule ${pattern}. Do not retry this command or an equivalent form. The blocked command was: ${command}`;
}

function policyFailureReason(command, error) {
  const message = error instanceof Error ? error.message : String(error);
  return `Command denied because command-approves could not read or parse ${RULES_PATH}: ${message}. Fix rules.json before retrying. The blocked command was: ${command}`;
}

function preToolDeny(reason) {
  return {
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision: 'deny',
      permissionDecisionReason: reason,
    },
  };
}

function preToolAllow(reason) {
  return {
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision: 'allow',
      permissionDecisionReason: reason,
    },
  };
}

function permissionDecision(behavior, message) {
  const decision = { behavior };
  if (message !== undefined) decision.message = message;
  return {
    hookSpecificOutput: {
      hookEventName: 'PermissionRequest',
      decision,
    },
  };
}

function detectAskLocale(environment = process.env, systemLocale) {
  const explicit = environment.COMMAND_APPROVES_LOCALE;
  const configured = explicit || environment.LC_ALL || environment.LC_MESSAGES
    || environment.LANG || systemLocale
    || Intl.DateTimeFormat().resolvedOptions().locale;
  return String(configured).toLowerCase().replace('_', '-').startsWith('zh') ? 'zh' : 'en';
}

function askDialogTitle(locale = 'en') {
  return ASK_DIALOG_COPY[locale === 'zh' ? 'zh' : 'en'].title;
}

function buildAskDialogMessage({ command, cwd, pattern }, locale = 'en') {
  const copy = ASK_DIALOG_COPY[locale === 'zh' ? 'zh' : 'en'];
  const lines = [
    copy.prompt,
    '',
    `${copy.command}${command}`,
    `${copy.rule}${pattern}`,
  ];
  if (cwd) lines.push(`${copy.cwd}${cwd}`);
  lines.push('', copy.decision);
  return lines.join('\r\n');
}

function renderAskDialogMessage(prompt, locale = 'en') {
  return typeof prompt === 'string' ? prompt : buildAskDialogMessage(prompt, locale);
}

function showAskDialog(prompt, timeoutMs = DEFAULT_ASK_DIALOG_TIMEOUT_MS) {
  if (process.platform !== 'win32') {
    throw new Error('Windows approval dialogs are not available on this platform');
  }

  const locale = detectAskLocale();
  const message = renderAskDialogMessage(prompt, locale);
  const title = askDialogTitle(locale);
  const script = [
    'Add-Type -AssemblyName System.Windows.Forms',
    '[System.Windows.Forms.Application]::EnableVisualStyles()',
    `$title = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${Buffer.from(title).toString('base64')}'))`,
    `$message = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${Buffer.from(message).toString('base64')}'))`,
    '$answer = [System.Windows.Forms.MessageBox]::Show(',
    '  $message,',
    '  $title,',
    '  [System.Windows.Forms.MessageBoxButtons]::YesNo,',
    '  [System.Windows.Forms.MessageBoxIcon]::Question,',
    '  [System.Windows.Forms.MessageBoxDefaultButton]::Button2',
    ')',
    'if ($answer -eq [System.Windows.Forms.DialogResult]::Yes) { exit 0 }',
    'exit 1',
  ].join('\n');
  const encodedScript = Buffer.from(script, 'utf16le').toString('base64');
  const result = spawnSync(
    'powershell.exe',
    ['-NoLogo', '-NoProfile', '-STA', '-EncodedCommand', encodedScript],
    {
      encoding: 'utf8',
      timeout: timeoutMs,
      windowsHide: true,
    },
  );

  if (result.error) throw result.error;
  if (result.status === 0) return true;
  if (result.status === 1) return false;
  const detail = result.stderr.trim();
  throw new Error(detail || 'approval dialog was closed without a decision');
}

function askDenialReason(command, rule, error) {
  const suffix = `Matched rule "${rule.pattern}". The command was: ${command}`;
  if (error === undefined) {
    return `Command denied because it was not approved in the command-approves dialog. ${suffix}`;
  }
  const message = error instanceof Error ? error.message : String(error);
  return `Command denied because command-approves could not show the approval dialog: ${message}. ${suffix}`;
}

function evaluateAsk(eventName, event, command, outcome, options) {
  const prompt = {
    command,
    cwd: typeof event.cwd === 'string' ? event.cwd : '',
    pattern: outcome.rule.pattern,
  };
  let approved;
  try {
    const confirmAsk = options.confirmAsk || showAskDialog;
    approved = confirmAsk(
      prompt,
      options.dialogTimeoutMs || DEFAULT_ASK_DIALOG_TIMEOUT_MS,
    );
  } catch (error) {
    const reason = askDenialReason(command, outcome.rule, error);
    return eventName === 'PermissionRequest'
      ? permissionDecision('deny', reason)
      : preToolDeny(reason);
  }

  if (approved === true) {
    return eventName === 'PermissionRequest'
      ? permissionDecision('allow')
      : preToolAllow('Approved in the command-approves dialog.');
  }

  const reason = askDenialReason(command, outcome.rule);
  return eventName === 'PermissionRequest'
    ? permissionDecision('deny', reason)
    : preToolDeny(reason);
}

function failClosed(eventName, command, error) {
  const reason = policyFailureReason(command, error);
  if (eventName === 'PermissionRequest') return permissionDecision('deny', reason);
  return preToolDeny(reason);
}

function evaluateEvent(event, options = {}) {
  const eventName = eventNameOf(event);
  if (eventName === undefined) return undefined;
  if (String(event.tool_name || '').toLowerCase() !== 'bash') return undefined;

  const command = commandOf(event.tool_input);
  if (command === undefined) return undefined;

  let outcome;
  try {
    outcome = evaluateCommand(command, loadRules());
  } catch (error) {
    return failClosed(eventName, command, error);
  }

  if (outcome.action === 'deny') {
    const reason = denyReason(command, outcome.rule);
    return eventName === 'PermissionRequest'
      ? permissionDecision('deny', reason)
      : preToolDeny(reason);
  }

  if (outcome.action === 'ask') {
    return evaluateAsk(eventName, event, command, outcome, options);
  }

  if (eventName === 'PermissionRequest' && outcome.action === 'allow') {
    return permissionDecision('allow');
  }
  return undefined;
}

function dialogTimeoutMsFromArgv(argv) {
  for (const argument of argv) {
    if (!argument.startsWith(DIALOG_TIMEOUT_ARG)) continue;
    const value = Number(argument.slice(DIALOG_TIMEOUT_ARG.length));
    if (Number.isSafeInteger(value) && value > 0) return value;
  }
  return DEFAULT_ASK_DIALOG_TIMEOUT_MS;
}

function main() {
  let input = '';
  process.stdin.setEncoding('utf8');
  process.stdin.on('data', (chunk) => {
    input += chunk;
    if (input.length > MAX_INPUT_LENGTH) {
      process.stdout.write(JSON.stringify(preToolDeny(
        'Command denied because the command-approves hook input exceeded its size limit.',
      )));
      process.exitCode = 0;
      process.stdin.destroy();
    }
  });
  process.stdin.on('end', () => {
    if (input.length > MAX_INPUT_LENGTH) return;
    try {
      const event = JSON.parse(input);
      const output = evaluateEvent(event, {
        dialogTimeoutMs: dialogTimeoutMsFromArgv(process.argv.slice(2)),
      });
      if (output !== undefined) process.stdout.write(JSON.stringify(output));
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      process.stdout.write(JSON.stringify(preToolDeny(
        `Command denied because the command-approves hook received invalid input: ${message}`,
      )));
    }
  });
}

if (require.main === module) main();

module.exports = {
  DEFAULT_ASK_DIALOG_TIMEOUT_MS,
  RULES_PATH,
  analyzeCommand,
  askDialogTitle,
  buildAskDialogMessage,
  detectAskLocale,
  dialogTimeoutMsFromArgv,
  evaluateCommand,
  evaluateEvent,
  loadRules,
  matchesRule,
  normalizeExpression,
  normalizeRules,
  renderAskDialogMessage,
  tokenizeScript,
};
