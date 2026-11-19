// Windows SSH servers with a PowerShell DefaultShell (and none-auth servers):
// regression tests for the fixes that make dsh-remote work against them.
//
// Covered failures (all observed against a real simple-ssh server on Windows
// with DefaultShell = PowerShell 7):
//   1. buildOpts refused to dial with no password/key/agent, although ssh2
//      offers `none` auth first and such servers accept it.
//   2. `cmd /c if exist "p" (echo Y) else (echo N)` — PowerShell parses the
//      parentheses and the probe fails; the paren-free form works everywhere.
//   3. `cmd /c where bash` returns the WSL stub C:\Windows\System32\bash.exe
//      first; it must be filtered and candidates verified with `uname -s`.
//   4. exec wrapped Git Bash as `"C:\…\bash.exe" -s`, which PowerShell cannot
//      parse; it must go through `cmd /c "…" -s`.
//   5. `cmd /c fsutil fsinfo drives` under Git Bash: MSYS rewrites /c to C:/,
//      cmd starts interactively and the regex harvests the prompt — always
//      one drive. Get-PSDrive first, `cmd //c fsutil` as fallback.
//   6. toSftpPath('C:\') produced '/C:/', which sftp servers clean to 'C:'
//      (the session's current directory ON the drive, not the drive root).
import { test } from 'node:test'
import assert from 'node:assert/strict'

import { SshPool } from '../lib/pool.js'
import { SystemOpenSshPool } from '../lib/openssh.js'
import { listRemoteDrives } from '../lib/remote-fs.js'
import { toSftpPath, connectProbeCommand } from '../lib/paths.js'
import { startFakeSsh } from './harness/fake-ssh.js'
import { createHost, machine } from './harness/plugin-host.js'

const baseConfig = (over = {}) => ({
  host: '127.0.0.1',
  port: 22,
  username: 'root',
  password: '',
  privateKeyPath: '',
  passphrase: '',
  hostKeyMode: 'off',
  commandTimeoutMs: 2000,
  connectTimeoutMs: 2000,
  maxOutputChars: 10000,
  ...over,
})

// ---------------------------------------------------------------------------
// 7. A missing/NaN maxOutputChars must not silently discard ALL exec output:
//    `Math.max(NaN * 4, 1MB)` is NaN, and `len < NaN` never accumulates.
// ---------------------------------------------------------------------------
test('exec: a config without maxOutputChars still returns command output', async () => {
  const srv = await startFakeSsh({ users: {} })
  const cfg = srv.machine({ password: '', privateKeyPath: '' })
  delete cfg.maxOutputChars
  const pool = new SshPool(cfg)
  try {
    const r = await pool.exec('echo hello')
    assert.equal(r.code, 0)
    assert.match(String(r.stdout), /hello/, 'stdout must not be silently emptied by a missing output cap')
  } finally {
    await pool.close()
    await srv.close()
  }
})

// ---------------------------------------------------------------------------
// 1. none-auth: a credential-less machine must dial, not throw pre-flight.
// ---------------------------------------------------------------------------
test('none-auth: a server that accepts `none` connects with no password/key/agent', async () => {
  // users: {} makes the fake server accept ANY auth method, including none.
  const srv = await startFakeSsh({ users: {} })
  const pool = new SshPool(srv.machine({ password: '', privateKeyPath: '' }))
  try {
    const client = await pool.connect()
    assert.ok(client, 'connect() must resolve against a none-auth server')
  } finally {
    await pool.close()
    await srv.close()
  }
})

test('none-auth: useAgent without an agent socket still reports the agent problem after the dial', async () => {
  const savedSock = process.env.SSH_AUTH_SOCK
  delete process.env.SSH_AUTH_SOCK
  const srv = await startFakeSsh({ rejectAll: true })
  const pool = new SshPool(srv.machine({ password: '', privateKeyPath: '', useAgent: true }))
  try {
    await assert.rejects(pool.connect(), /SSH agent|SSH_AUTH_SOCK/)
  } finally {
    await pool.close()
    await srv.close()
    if (savedSock !== undefined) process.env.SSH_AUTH_SOCK = savedSock
  }
})

// ---------------------------------------------------------------------------
// 2. _cmdExists must not use the parenthesized if-exist form.
// ---------------------------------------------------------------------------
test('windows: _cmdExists uses the paren-free if exist form (PowerShell-safe)', async () => {
  const pool = new SshPool(baseConfig())
  const seen = []
  pool._execRaw = async (cmd) => { seen.push(cmd); return { code: 0, stdout: 'Y\r\n', stderr: '' } }
  const ok = await pool._cmdExists('C:\\Programs\\Git\\bin\\bash.exe')
  assert.equal(ok, true)
  assert.equal(seen.length, 1)
  assert.ok(!seen[0].includes('(echo'), `parenthesized if exist breaks PowerShell DefaultShell: ${seen[0]}`)
  assert.ok(seen[0].startsWith('cmd /c if exist '), seen[0])
})

// ---------------------------------------------------------------------------
// 3. Git Bash resolution: filter WSL stubs, verify with uname, find Git via
//    `where git`, and fall back to native when no real Git Bash exists.
// ---------------------------------------------------------------------------
function windowsExecMock(answers) {
  const seen = []
  const fn = async (cmd) => {
    seen.push(cmd)
    for (const [pattern, reply] of answers) {
      if (typeof pattern === 'string' ? cmd === pattern : pattern.test(cmd)) return reply
    }
    return { code: 1, stdout: '', stderr: '' }
  }
  fn.seen = seen
  return fn
}

const GIT = 'C:\\Programs\\Git\\bin\\bash.exe'
const WSL_STUB = 'C:\\Windows\\System32\\bash.exe'
const ok = (stdout) => ({ code: 0, stdout, stderr: '' })

test('windows: where bash lists the WSL stub first — pick the verified Git Bash instead', async () => {
  const pool = new SshPool(baseConfig())
  pool._execRaw = windowsExecMock([
    ['cmd /c where bash', ok(`${WSL_STUB}\r\n${GIT}\r\n`)],
    [`cmd /c if exist "${GIT}" echo Y`, ok('Y\r\n')],
    [`cmd /c "${GIT}" -c "uname -s"`, ok('MINGW64_NT-10.0-26200\r\n')],
    [`cmd /c if exist "${WSL_STUB}" echo Y`, ok('Y\r\n')],
    [`cmd /c "${WSL_STUB}" -c "uname -s"`, ok('Linux\r\n')],
  ])
  await pool._resolveGitBash()
  assert.equal(pool.gitBashPath, GIT)
  assert.equal(pool.shellMode, 'git-bash')
})

test('windows: only the WSL stub on PATH — locate Git Bash next to `where git`', async () => {
  const pool = new SshPool(baseConfig())
  pool._execRaw = windowsExecMock([
    ['cmd /c where bash', ok(`${WSL_STUB}\r\n`)],
    ['cmd /c where git', ok('C:\\Programs\\Git\\cmd\\git.exe\r\n')],
    [`cmd /c if exist "${GIT}" echo Y`, ok('Y\r\n')],
    [`cmd /c "${GIT}" -c "uname -s"`, ok('MINGW64_NT-10.0-26200\r\n')],
    [`cmd /c if exist "${WSL_STUB}" echo Y`, ok('Y\r\n')],
    [`cmd /c "${WSL_STUB}" -c "uname -s"`, ok('Linux\r\n')],
  ])
  await pool._resolveGitBash()
  assert.equal(pool.gitBashPath, GIT)
  assert.equal(pool.shellMode, 'git-bash')
})

test('windows: no real Git Bash anywhere — fall back to native, not git-bash with an empty path', async () => {
  const pool = new SshPool(baseConfig())
  pool._execRaw = windowsExecMock([
    ['cmd /c where bash', ok(`${WSL_STUB}\r\n`)],
    [`cmd /c if exist "${WSL_STUB}" echo Y`, ok('Y\r\n')],
    [`cmd /c "${WSL_STUB}" -c "uname -s"`, ok('Linux\r\n')],
  ])
  await pool._resolveGitBash()
  assert.equal(pool.gitBashPath, '')
  assert.equal(pool.shellMode, 'native')
})

// ---------------------------------------------------------------------------
// 4. exec must invoke Git Bash through cmd /c (PowerShell-safe).
// ---------------------------------------------------------------------------
test('windows: exec pipes the script to `cmd /c "<bash>" -s`', async () => {
  const pool = new SshPool(baseConfig())
  pool.platform = 'windows'
  pool.gitBashPath = GIT
  const seen = []
  pool._execRaw = async (cmd, opts, writer) => {
    seen.push({ cmd, opts, writer })
    return { code: 0, stdout: 'ok', stderr: '' }
  }
  const script = "printf '%s' \"a && b | c\""
  await pool.exec(script)
  assert.equal(seen.length, 1)
  assert.equal(seen[0].cmd, `cmd /c "${GIT}" -s`)
  assert.equal(typeof seen[0].writer, 'function', 'the script must travel on stdin')
})

// ---------------------------------------------------------------------------
// openssh backend: the same resolution + exec rules apply.
// ---------------------------------------------------------------------------
const opensshConfig = (over = {}) => baseConfig({ backend: 'openssh', hostKeyMode: 'accept-new', ...over })

test('openssh: WSL stub filtered, Git Bash verified via uname probe', async () => {
  const pool = new SystemOpenSshPool(opensshConfig())
  const seen = []
  pool._runSsh = async (args) => {
    const cmd = args[args.length - 1]
    seen.push(cmd)
    if (cmd === 'cmd /c where bash') return ok(`${WSL_STUB}\r\n${GIT}\r\n`)
    if (cmd === `cmd /c if exist "${GIT}" echo Y`) return ok('Y\r\n')
    if (cmd === `cmd /c "${GIT}" -c "uname -s"`) return ok('MINGW64_NT-10.0-26200\r\n')
    if (cmd === `cmd /c if exist "${WSL_STUB}" echo Y`) return ok('Y\r\n')
    if (cmd === `cmd /c "${WSL_STUB}" -c "uname -s"`) return ok('Linux\r\n')
    return { code: 1, stdout: '', stderr: '' }
  }
  await pool._resolveGitBash()
  assert.equal(pool.gitBashPath, GIT)
  assert.equal(pool.shellMode, 'git-bash')
})

test('openssh: only WSL stub — find Git Bash via where git; none → native', async () => {
  const pool = new SystemOpenSshPool(opensshConfig())
  pool._runSsh = async (args) => {
    const cmd = args[args.length - 1]
    if (cmd === 'cmd /c where bash') return ok(`${WSL_STUB}\r\n`)
    if (cmd === 'cmd /c where git') return ok('C:\\Programs\\Git\\cmd\\git.exe\r\n')
    if (cmd === `cmd /c if exist "${GIT}" echo Y`) return ok('Y\r\n')
    if (cmd === `cmd /c "${GIT}" -c "uname -s"`) return ok('MINGW64_NT-10.0-26200\r\n')
    if (cmd === `cmd /c if exist "${WSL_STUB}" echo Y`) return ok('Y\r\n')
    if (cmd === `cmd /c "${WSL_STUB}" -c "uname -s"`) return ok('Linux\r\n')
    return { code: 1, stdout: '', stderr: '' }
  }
  await pool._resolveGitBash()
  assert.equal(pool.gitBashPath, GIT)
  assert.equal(pool.shellMode, 'git-bash')

  const bare = new SystemOpenSshPool(opensshConfig())
  bare._runSsh = async (args) => {
    const cmd = args[args.length - 1]
    if (cmd === 'cmd /c where bash') return ok(`${WSL_STUB}\r\n`)
    if (cmd === `cmd /c if exist "${WSL_STUB}" echo Y`) return ok('Y\r\n')
    if (cmd === `cmd /c "${WSL_STUB}" -c "uname -s"`) return ok('Linux\r\n')
    return { code: 1, stdout: '', stderr: '' }
  }
  await bare._resolveGitBash()
  assert.equal(bare.gitBashPath, '')
  assert.equal(bare.shellMode, 'native')
})

test('openssh: exec invokes Git Bash through cmd /c with the script on stdin', async () => {
  const pool = new SystemOpenSshPool(opensshConfig())
  pool.platform = 'windows'
  pool.gitBashPath = GIT
  const seen = []
  pool._runSsh = async (args, opts) => { seen.push({ args, opts }); return { code: 0, stdout: 'ok', stderr: '' } }
  const script = "printf '%s' \"a && b | c\""
  await pool.exec(script)
  assert.equal(seen.length, 1)
  assert.equal(seen[0].args[seen[0].args.length - 1], `cmd /c "${GIT}" -s`)
  assert.equal(seen[0].opts.stdin, script)
})

// ---------------------------------------------------------------------------
// 5. Drive enumeration under a Git-Bash exec wrapper.
// ---------------------------------------------------------------------------
function drivePool(answers) {
  const seen = []
  return {
    config: { commandTimeoutMs: 8000 },
    seen,
    async exec(cmd) {
      seen.push(cmd)
      if (Object.hasOwn(answers, cmd)) return answers[cmd]
      throw new Error(`unexpected command: ${cmd}`)
    },
  }
}

test('drives: Get-PSDrive enumerates every drive even when fsutil output is a cmd prompt', async () => {
  // The MSYS /c-rewrite bug: `cmd /c fsutil …` starts cmd interactively and
  // its "output" is the banner + prompt, from which the old regex harvests C:.
  const pool = drivePool({
    'powershell -NoProfile -NonInteractive -Command "(Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue).Name"':
      { code: 0, stdout: 'C\r\nD\r\nX\r\n', stderr: '' },
  })
  const drives = await listRemoteDrives(pool)
  assert.deepEqual(drives.map((d) => d.path), ['C:\\', 'D:\\', 'X:\\'])
  assert.ok(drives.every((d) => d.drive === true && d.type === 'dir'))
})

test('drives: fsutil fallback uses `cmd //c` (MSYS-safe) when PowerShell is unavailable', async () => {
  const pool = drivePool({
    'powershell -NoProfile -NonInteractive -Command "(Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue).Name"':
      { code: 1, stdout: '', stderr: 'not found' },
    'cmd //c fsutil fsinfo drives': { code: 0, stdout: 'Drives: C:\\ D:\\ X:\\ \r\n', stderr: '' },
  })
  const drives = await listRemoteDrives(pool)
  assert.deepEqual(drives.map((d) => d.path), ['C:\\', 'D:\\', 'X:\\'])
})

test('drives: Git-Bash `ls -d /[a-z]` fallback still works', async () => {
  const pool = drivePool({
    'powershell -NoProfile -NonInteractive -Command "(Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue).Name"':
      { code: 1, stdout: '', stderr: '' },
    'cmd //c fsutil fsinfo drives': { code: 1, stdout: '', stderr: '' },
    'ls -d /[a-z] 2>/dev/null': { code: 0, stdout: '/c\n/d\n', stderr: '' },
  })
  const drives = await listRemoteDrives(pool)
  assert.deepEqual(drives.map((d) => d.path), ['C:\\', 'D:\\'])
})

// ---------------------------------------------------------------------------
// 6. Drive roots must reach the SFTP server as `C:/`, not `/C:/`.
// ---------------------------------------------------------------------------
test('toSftpPath: a drive ROOT goes out drive-relative (C:/), deeper paths keep /D:/ form', () => {
  assert.equal(toSftpPath('C:\\'), 'C:/')
  assert.equal(toSftpPath('D:\\'), 'D:/')
  assert.equal(toSftpPath('D:\\Code'), '/D:/Code')
  assert.equal(toSftpPath('C:/Users/x'), '/C:/Users/x')
  assert.equal(toSftpPath('/home/user'), '/home/user')
})

// ---------------------------------------------------------------------------
// 7. The connect probe must not assume a POSIX shell. `true` is a binary that
//    does not exist on a Windows DefaultShell of PowerShell — the dial itself
//    succeeded, yet the probe failed with "true: The term 'true' is not
//    recognized…". And BARE `echo` is no better: PowerShell aliases it to
//    Write-Output, which demands an InputObject. `echo <arg>` is the portable
//    no-op on every shell dsh-remote meets (sh/bash builtin, PowerShell alias).
// ---------------------------------------------------------------------------
test('connectProbeCommand: the probe is shell-portable (echo with an argument, never POSIX true or bare echo)', () => {
  const probe = connectProbeCommand()
  assert.equal(probe, 'echo dsh-probe')
  assert.notEqual(probe, 'true')
  assert.notEqual(probe, 'echo', 'bare echo fails PowerShell Write-Output (missing InputObject)')
  assert.ok(/^echo\s+\S+/.test(probe), 'the probe must carry an argument for PowerShell')
})

test('openssh connect: the liveness probe it sends is the portable echo-with-arg, not true', async () => {
  const pool = new SystemOpenSshPool(baseConfig({ backend: 'openssh', hostKeyMode: 'off' }))
  const seen = []
  pool._runSsh = async (args) => { seen.push(args); return { code: 0, stdout: '', stderr: '' } }
  await pool.connect()
  assert.ok(seen.length >= 1, 'connect() must probe the target')
  assert.equal(seen[0][seen[0].length - 1], connectProbeCommand(), 'the probe command must work under a PowerShell DefaultShell')
})

test('test-connect: a PowerShell-like shell (no true, bare echo needs InputObject) still probes OK', async () => {
  // A fake server that accepts none-auth and models a Windows PowerShell
  // DefaultShell: the POSIX `true` binary is missing AND bare `echo` fails
  // (Write-Output demands an InputObject); only `echo <arg>` succeeds.
  const srv = await startFakeSsh({
    users: {},
    onExec: (cmd) => {
      if (/^echo\s+\S+/.test(cmd)) return { code: 0, stdout: cmd.replace(/^echo\s+/, '') + '\n', stderr: '' }
      if (cmd === 'echo') return { code: 1, stdout: '', stderr: 'Write-Output: Cannot process command because of one or more missing mandatory parameters: InputObject.' }
      if (cmd === 'true') return { code: 1, stdout: '', stderr: "true: The term 'true' is not recognized as a name of a cmdlet" }
      return null // everything else falls through to the fake's table
    },
  })
  const host = await createHost({
    machines: [machine({ host: '127.0.0.1', port: srv.port, username: 'root', password: 'pw' })],
  })
  try {
    const list = await host.call('/dsh-remote/machines', { method: 'GET' })
    const rec = list.json.machines[0]
    const probe = await host.call('/dsh-remote/test-connect', {
      body: { id: rec.id, host: '127.0.0.1', port: srv.port, username: 'root', password: '' },
    })
    assert.equal(probe.json.ok, true, `probe must survive a PowerShell shell: ${probe.json.error}`)
  } finally {
    await host.dispose()
    await srv.close()
  }
})