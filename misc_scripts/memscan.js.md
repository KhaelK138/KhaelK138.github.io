---
layout: blank
pagetitle: 
---

```javascript
// memscan.js
'use strict';

/*
CheatEngine-ish memory scanner for numeric values (Frida).

FAST range scanning strategy:
- Bulk-read each range with Memory.readByteArray()
- Scan a local DataView buffer
- Store results per-range as blocks:
    { base, size, step, type, offsets: Uint32Array, last: (Float32Array|Int32Array|Uint32Array) }

Commands:
  msRanges([prot="rw-"])
  msNew(value, [type="u32"|"s32"|"f32"], [prot="rw-"])
  msNewRange(min, max, [type="f32"|"u32"|"s32"], [prot="rw-"], [step=4])
  msUse("exact"|"range")
  msRefine("eq"|"changed"|"unchanged"|"inc"|"dec"|"gt"|"lt", [value])
  msUndoRefine()
  msList([limit=40])
  msWrite(index, value)
  msWriteAll(value)
  msFreeze(index, [intervalMs=100])
  msUnfreeze(index)
  msUnfreezeAll()
  msClear()
  msHelp()
*/

const RANGE_CHUNK = 1024 * 1024;
const DEBUG_RANGE = false;
const FLOAT_EPSILON = 0.0001;

const state = {
  type: 'u32',
  active: 'exact',

  exact: [],
  exactPrev: null,

  rangeBlocks: [],
  rangeBlocksPrev: null,

  frozen: new Map(),

  last: {
    ranges: 0,
    failedRanges: 0,
    readErrors: 0,
    hits: 0
  }
};

// ---------- Type helpers ----------

function clampType(t) {
  const ok = new Set(['u32', 's32', 'f32']);
  return ok.has(t) ? t : 'u32';
}

function enumerateRanges(protection) {
  return Process.enumerateRanges({ protection, coalesce: true });
}

function fmt(v, t) {
  if (t === 'f32') return Number.isFinite(v) ? v.toFixed(6) : String(v);
  return String(v);
}

function makeLastArray(t, n) {
  if (t === 'f32') return new Float32Array(n);
  if (t === 's32') return new Int32Array(n);
  return new Uint32Array(n);
}

function dvRead(dv, off, t) {
  const byteLen = dv.byteLength;
  if (off < 0 || off + 4 > byteLen) return null;

  if (t === 'f32') return dv.getFloat32(off, true);
  if (t === 's32') return dv.getInt32(off, true);
  return dv.getUint32(off, true) >>> 0;
}

function floatEq(a, b) {
  return Math.abs(a - b) < FLOAT_EPSILON;
}

function valuesEqual(a, b, t) {
  if (t === 'f32') return floatEq(a, b);
  return a === b;
}

function readAt(addr, t) {
  switch (t) {
    case 'u32': return addr.readU32() >>> 0;
    case 's32': return addr.readS32() | 0;
    case 'f32': return addr.readFloat();
    default:    return addr.readU32() >>> 0;
  }
}

function writeAt(addr, t, v) {
  switch (t) {
    case 'u32': addr.writeU32(v >>> 0); break;
    case 's32': addr.writeS32(v | 0); break;
    case 'f32': addr.writeFloat(+v); break;
    default:    addr.writeU32(v >>> 0); break;
  }
}

function safeRead(addr, t) {
  try {
    return { ok: true, v: readAt(addr, t) };
  } catch (_) {
    return { ok: false, v: null };
  }
}

function safeWrite(addr, t, v) {
  try {
    writeAt(addr, t, v);
    const after = readAt(addr, t);
    return { ok: true, after };
  } catch (e) {
    return { ok: false, err: String(e) };
  }
}

// ---------- Active list access ----------

function activeCount() {
  if (state.active === 'exact') return state.exact.length;
  let n = 0;
  for (const b of state.rangeBlocks) n += b.offsets.length;
  return n;
}

function rangeIndexToEntry(index) {
  let i = index | 0;
  for (const block of state.rangeBlocks) {
    const len = block.offsets.length;
    if (i < len) {
      const off = block.offsets[i];
      return { block, j: i, addr: block.base.add(off) };
    }
    i -= len;
  }
  return null;
}

function getAddrByIndex(index) {
  if (state.active === 'exact') {
    if (index >= 0 && index < state.exact.length) {
      return state.exact[index].addr;
    }
    return null;
  }
  const entry = rangeIndexToEntry(index);
  return entry ? entry.addr : null;
}

// ---------- Pattern helpers ----------

function u32ToPattern(value) {
  const v = value >>> 0;
  const b0 = (v & 0xff).toString(16).padStart(2, '0');
  const b1 = ((v >>> 8) & 0xff).toString(16).padStart(2, '0');
  const b2 = ((v >>> 16) & 0xff).toString(16).padStart(2, '0');
  const b3 = ((v >>> 24) & 0xff).toString(16).padStart(2, '0');
  return `${b0} ${b1} ${b2} ${b3}`;
}

function f32ToPattern(value) {
  const p = Memory.alloc(4);
  p.writeFloat(+value);
  const u = p.readU32() >>> 0;
  return u32ToPattern(u);
}

function valueToPattern(value, t) {
  if (t === 'f32') return f32ToPattern(value);
  return u32ToPattern(value >>> 0);
}

// ---------- Bulk read helper ----------

function readChunk(base, size) {
  const buf = base.readByteArray(size);
  if (buf === null) throw new Error('readByteArray returned null');
  return buf;
}

// ---------- Undo snapshot helpers ----------

function snapshotExact() {
  return state.exact.map(e => ({ addr: e.addr, last: e.last }));
}

function snapshotRangeBlocks() {
  return state.rangeBlocks.map(b => ({
    base: b.base,
    size: b.size,
    step: b.step,
    type: b.type,
    offsets: new Uint32Array(b.offsets),
    last: b.last.slice()
  }));
}

// ---------- Public API ----------

globalThis.msRanges = function (protection = 'rw-') {
  const ranges = enumerateRanges(protection);
  console.log(`[*] Ranges for protection="${protection}": ${ranges.length}`);
  for (let i = 0; i < Math.min(10, ranges.length); i++) {
    const r = ranges[i];
    const prot = r.protection !== undefined ? r.protection : protection;
    console.log(`  [${i}] ${r.base}  size=${r.size}  prot=${prot}`);
  }
  console.log(`[*] Tip: if 0 ranges, try msRanges('r--') or msRanges('r-x').`);
};

globalThis.msUse = function (which) {
  const w = (which || '').toLowerCase();
  if (w !== 'exact' && w !== 'range') {
    console.log('Usage: msUse("exact"|"range")');
    return;
  }
  state.active = w;
  console.log(`[*] Active list set to: ${w} (${activeCount()} match(es), type=${state.type})`);
};

globalThis.msClear = function () {
  state.exact = [];
  state.exactPrev = null;
  state.rangeBlocks = [];
  state.rangeBlocksPrev = null;
  msUnfreezeAll();
  console.log('[*] Cleared exact + range matches and frozen addresses.');
};

globalThis.msNew = function (value, type = 'u32', protection = 'rw-') {
  if (typeof value !== 'number') {
    console.log('Usage: msNew(<number>, [type="u32"|"s32"|"f32"], [protection="rw-"])');
    return;
  }

  state.type = clampType(type);
  state.active = 'exact';
  state.exact = [];
  state.exactPrev = null;

  const pattern = valueToPattern(value, state.type);
  console.log(`[*] Exact scan: value=${value} type=${state.type} prot=${protection} pattern=${pattern}`);

  const ranges = enumerateRanges(protection);
  let total = 0;
  let failedRanges = 0;

  for (const r of ranges) {
    try {
      const hits = Memory.scanSync(r.base, r.size, pattern);
      for (const h of hits) {
        const res = safeRead(h.address, state.type);
        if (!res.ok) continue;
        state.exact.push({ addr: h.address, last: res.v });
        total++;
      }
    } catch (_) {
      failedRanges++;
    }
  }

  console.log(`[*] Scan complete — ${total} hit(s). Ranges scanned=${ranges.length}, failed=${failedRanges}.`);
  console.log(`[*] Active list: exact. Use msList(), msRefine(), msWrite().`);
};

globalThis.msNewRange = function (min, max, type = 'f32', protection = 'rw-', step = 4, chunkSize = RANGE_CHUNK) {
  if (typeof min !== 'number' || typeof max !== 'number') {
    console.log('Usage: msNewRange(<min>, <max>, [type="f32"|"u32"|"s32"], [protection="rw-"], [step=4], [chunkSize])');
    return;
  }
  if (max < min) { const t = min; min = max; max = t; }

  state.type = clampType(type);
  state.active = 'range';
  state.rangeBlocks = [];
  state.rangeBlocksPrev = null;

  step = step | 0;
  if (step <= 0) step = 4;

  chunkSize = chunkSize | 0;
  if (chunkSize <= 0) chunkSize = RANGE_CHUNK;

  console.log(`[*] Range scan (CHUNKED): min=${min} max=${max} type=${state.type} prot=${protection} step=${step} chunk=${chunkSize}`);
  if (state.type == 'f32') {
    console.log(`[*] Float scans can take a few minutes, hold tight...`)
  }
  const ranges = enumerateRanges(protection);

  let totalHits = 0;
  let failedRanges = 0;
  let failedChunks = 0;
  let readErrors = 0;

  for (const r of ranges) {
    const size = r.size >>> 0;
    if (size < 4) continue;

    const offsetsTmp = [];
    const valuesTmp = [];

    let anyChunkOk = false;

    for (let rel = 0; rel < size; rel += chunkSize) {
      const remaining = size - rel;
      // Only add overlap if there's another chunk after this one
      const needsOverlap = remaining > chunkSize;
      const thisChunk = needsOverlap ? chunkSize + 3 : remaining;

      let buf, dv;
      try {
        buf = readChunk(r.base.add(rel), thisChunk);
        dv = new DataView(buf);
        anyChunkOk = true;
      } catch (e) {
        failedChunks++;
        if (DEBUG_RANGE) console.log(`[dbg] chunk read failed @${r.base.add(rel)} size=${thisChunk}: ${e}`);
        continue;
      }

      const limit = thisChunk - 4;
      let startOff = 0;
      const mod = (rel % step);
      if (mod !== 0) startOff = (step - mod);

      for (let off = startOff; off <= limit; off += step) {
        const v = dvRead(dv, off, state.type);
        if (v === null) {
          readErrors++;
          continue;
        }
        if (state.type === 'f32' && Number.isNaN(v)) continue;

        if (v >= min && v <= max) {
          const absOff = (rel + off) >>> 0;
          offsetsTmp.push(absOff);
          valuesTmp.push(v);
        }
      }
    }

    if (!anyChunkOk) {
      failedRanges++;
      if (DEBUG_RANGE) console.log(`[dbg] range read failed entirely: ${r.base} size=${r.size}`);
      continue;
    }

    if (offsetsTmp.length > 0) {
      const offsets = new Uint32Array(offsetsTmp);
      const last = makeLastArray(state.type, offsetsTmp.length);
      for (let i = 0; i < valuesTmp.length; i++) last[i] = valuesTmp[i];

      state.rangeBlocks.push({
        base: r.base,
        size: r.size,
        step,
        type: state.type,
        offsets,
        last
      });

      totalHits += offsets.length;
    }
  }

  console.log(`[*] Scan complete — ${totalHits} hit(s). Ranges scanned=${ranges.length}, failedRanges=${failedRanges}, failedChunks=${failedChunks}, readErrors=${readErrors}.`);
  console.log(`[*] Active list: range. Use msList(), msRefine(), msWrite().`);
};

globalThis.msList = function (limit = 40) {
  const lim = Math.max(0, limit | 0);

  if (state.active === 'exact') {
    const n = Math.min(lim, state.exact.length);
    console.log(`[*] Listing ${n}/${state.exact.length} matches (type=${state.type}, active=exact)`);

    for (let i = 0; i < n; i++) {
      const m = state.exact[i];
      const res = safeRead(m.addr, state.type);
      const frozen = state.frozen.has(m.addr.toString()) ? ' [FROZEN]' : '';
      if (!res.ok) {
        console.log(`[${i}] ${m.addr}  <unreadable now>  last=${fmt(m.last, state.type)}${frozen}`);
        continue;
      }
      const cur = res.v;
      console.log(`[${i}] ${m.addr}  cur=${fmt(cur, state.type)}  last=${fmt(m.last, state.type)}${frozen}`);
      m.last = cur;
    }

    if (state.exact.length > n) console.log(`[*] ... (${state.exact.length - n} more)`);
    return;
  }

  const total = activeCount();
  const n = Math.min(lim, total);
  console.log(`[*] Listing ${n}/${total} matches (type=${state.type}, active=range)`);

  let printed = 0;
  let globalIndex = 0;

  for (const block of state.rangeBlocks) {
    if (printed >= n) break;

    for (let j = 0; j < block.offsets.length && printed < n; j++, globalIndex++) {
      const off = block.offsets[j];
      const addr = block.base.add(off);
      const res = safeRead(addr, state.type);
      const frozen = state.frozen.has(addr.toString()) ? ' [FROZEN]' : '';

      if (!res.ok) {
        console.log(`[${globalIndex}] ${addr}  <unreadable now>  last=${fmt(block.last[j], state.type)}${frozen}`);
        printed++;
        continue;
      }

      const cur = res.v;
      console.log(`[${globalIndex}] ${addr}  cur=${fmt(cur, state.type)}  last=${fmt(block.last[j], state.type)}${frozen}`);
      block.last[j] = cur;
      printed++;
    }
  }

  if (total > n) console.log(`[*] ... (${total - n} more)`);
};

globalThis.msRefine = function (mode, value) {
  const m = (mode || '').toLowerCase();
  const needsValue = new Set(['eq', 'gt', 'lt']);

  if (needsValue.has(m) && typeof value !== 'number') {
    console.log('Usage: msRefine("eq"|"gt"|"lt", <number>)');
    return;
  }

  if (!['eq', 'changed', 'unchanged', 'inc', 'dec', 'gt', 'lt'].includes(m)) {
    console.log('Usage: msRefine("eq"|"changed"|"unchanged"|"inc"|"dec"|"gt"|"lt", [value])');
    return;
  }

  if (state.active === 'exact') {
    state.exactPrev = snapshotExact();

    const before = state.exact.length;
    const kept = [];

    for (const entry of state.exact) {
      const res = safeRead(entry.addr, state.type);
      if (!res.ok) continue;

      const cur = res.v;
      let keep = false;

      if (m === 'eq') keep = valuesEqual(cur, value, state.type);
      else if (m === 'gt') keep = (cur > value);
      else if (m === 'lt') keep = (cur < value);
      else if (m === 'changed') keep = !valuesEqual(cur, entry.last, state.type);
      else if (m === 'unchanged') keep = valuesEqual(cur, entry.last, state.type);
      else if (m === 'inc') keep = (cur > entry.last);
      else if (m === 'dec') keep = (cur < entry.last);

      if (keep) kept.push({ addr: entry.addr, last: cur });
    }

    state.exact = kept;
    console.log(`[*] Refine(${m}${needsValue.has(m) ? `, ${value}` : ''}) — ${before} -> ${kept.length} (active=exact)`);
    return;
  }

  state.rangeBlocksPrev = snapshotRangeBlocks();

  const before = activeCount();
  const newBlocks = [];

  let failedBlocks = 0;
  let failedChunks = 0;
  let readErrors = 0;
  let keptTotal = 0;

  for (const block of state.rangeBlocks) {
    const offsets = block.offsets;
    const last = block.last;

    const keptOffsetsTmp = [];
    const keptValuesTmp = [];

    const buckets = new Map();
    const chunkSize = RANGE_CHUNK;

    for (let j = 0; j < offsets.length; j++) {
      const absOff = offsets[j] >>> 0;
      const chunkStart = Math.floor(absOff / chunkSize) * chunkSize;
      let arr = buckets.get(chunkStart);
      if (!arr) { arr = []; buckets.set(chunkStart, arr); }
      arr.push(j);
    }

    let anyOk = false;

    for (const [chunkStartRel, js] of buckets.entries()) {
      const remaining = (block.size >>> 0) - chunkStartRel;
      if (remaining <= 0) continue;

      const needsOverlap = remaining > chunkSize;
      const thisChunk = needsOverlap ? Math.min(remaining, chunkSize + 3) : remaining;

      let dv;
      try {
        const buf = readChunk(block.base.add(chunkStartRel), thisChunk);
        dv = new DataView(buf);
        anyOk = true;
      } catch (e) {
        failedChunks++;
        if (DEBUG_RANGE) console.log(`[dbg] refine chunk read failed @${block.base.add(chunkStartRel)} size=${thisChunk}: ${e}`);
        continue;
      }

      for (const j of js) {
        const absOff = offsets[j] >>> 0;
        const relOff = absOff - chunkStartRel;

        const cur = dvRead(dv, relOff, state.type);
        if (cur === null) {
          readErrors++;
          continue;
        }

        if (state.type === 'f32' && Number.isNaN(cur)) continue;

        const prev = last[j];
        let keep = false;

        if (m === 'eq') keep = valuesEqual(cur, value, state.type);
        else if (m === 'gt') keep = (cur > value);
        else if (m === 'lt') keep = (cur < value);
        else if (m === 'changed') keep = !valuesEqual(cur, prev, state.type);
        else if (m === 'unchanged') keep = valuesEqual(cur, prev, state.type);
        else if (m === 'inc') keep = (cur > prev);
        else if (m === 'dec') keep = (cur < prev);

        if (keep) {
          keptOffsetsTmp.push(absOff);
          keptValuesTmp.push(cur);
        }
      }
    }

    if (!anyOk) {
      failedBlocks++;
      continue;
    }

    if (keptOffsetsTmp.length > 0) {
      const newOffsets = new Uint32Array(keptOffsetsTmp);
      const newLast = makeLastArray(state.type, keptOffsetsTmp.length);
      for (let i = 0; i < keptValuesTmp.length; i++) newLast[i] = keptValuesTmp[i];

      newBlocks.push({
        base: block.base,
        size: block.size,
        step: block.step,
        type: block.type,
        offsets: newOffsets,
        last: newLast
      });

      keptTotal += newOffsets.length;
    }
  }

  state.rangeBlocks = newBlocks;

  console.log(
    `[*] Refine(${m}${needsValue.has(m) ? `, ${value}` : ''}) — ${before} -> ${keptTotal} (active=range)` +
    ` | failedBlocks=${failedBlocks} failedChunks=${failedChunks} readErrors=${readErrors}`
  );
};

globalThis.msUndoRefine = function () {
  if (state.active === 'exact') {
    if (state.exactPrev === null) {
      console.log('[!] No previous exact state to restore.');
      return;
    }
    const before = state.exact.length;
    state.exact = state.exactPrev;
    state.exactPrev = null;
    console.log(`[*] Undo refine: ${before} -> ${state.exact.length} (active=exact)`);
    return;
  }

  if (state.rangeBlocksPrev === null) {
    console.log('[!] No previous range state to restore.');
    return;
  }

  const before = activeCount();
  state.rangeBlocks = state.rangeBlocksPrev;
  state.rangeBlocksPrev = null;
  console.log(`[*] Undo refine: ${before} -> ${activeCount()} (active=range)`);
};

globalThis.msWrite = function (index, newValue) {
  if (typeof newValue !== 'number') {
    console.log('Usage: msWrite(<index>, <number>)');
    return;
  }

  const i = index | 0;
  const total = activeCount();

  if (i < 0 || i >= total) {
    console.log(`Usage: msWrite(<index 0..${total - 1}>, <number>)`);
    return;
  }

  if (state.active === 'exact') {
    const addr = state.exact[i].addr;
    const res = safeWrite(addr, state.type, newValue);

    if (!res.ok) {
      console.log(`[!] Write failed at ${addr}: ${res.err}`);
      return;
    }

    state.exact[i].last = res.after;
    console.log(`[*] Wrote ${fmt(newValue, state.type)} at ${addr} verify=${fmt(res.after, state.type)}`);
    return;
  }

  const entry = rangeIndexToEntry(i);
  if (entry === null) {
    console.log('[!] Internal error: index mapping failed');
    return;
  }

  const { block, j, addr } = entry;
  const res = safeWrite(addr, state.type, newValue);

  if (!res.ok) {
    console.log(`[!] Write failed at ${addr}: ${res.err}`);
    return;
  }

  block.last[j] = res.after;
  console.log(`[*] Wrote ${fmt(newValue, state.type)} at ${addr} verify=${fmt(res.after, state.type)}`);
};

globalThis.msWriteAll = function (newValue) {
  if (typeof newValue !== 'number') {
    console.log('Usage: msWriteAll(<number>)');
    return;
  }

  const total = activeCount();
  if (total === 0) {
    console.log('[!] No matches to write.');
    return;
  }

  let success = 0;
  let failed = 0;

  if (state.active === 'exact') {
    for (const entry of state.exact) {
      const res = safeWrite(entry.addr, state.type, newValue);
      if (res.ok) {
        entry.last = res.after;
        success++;
      } else {
        failed++;
      }
    }
  } else {
    for (const block of state.rangeBlocks) {
      for (let j = 0; j < block.offsets.length; j++) {
        const addr = block.base.add(block.offsets[j]);
        const res = safeWrite(addr, state.type, newValue);
        if (res.ok) {
          block.last[j] = res.after;
          success++;
        } else {
          failed++;
        }
      }
    }
  }

  console.log(`[*] WriteAll(${fmt(newValue, state.type)}): ${success} succeeded, ${failed} failed.`);
};

globalThis.msFreeze = function (index, intervalMs = 100) {
  const i = index | 0;
  const total = activeCount();

  if (i < 0 || i >= total) {
    console.log(`Usage: msFreeze(<index 0..${total - 1}>, [intervalMs=100])`);
    return;
  }

  const addr = getAddrByIndex(i);
  if (addr === null) {
    console.log('[!] Internal error: could not resolve address.');
    return;
  }

  const key = addr.toString();

  if (state.frozen.has(key)) {
    console.log(`[!] Address ${addr} is already frozen. Use msUnfreeze(${i}) first.`);
    return;
  }

  const res = safeRead(addr, state.type);
  if (!res.ok) {
    console.log(`[!] Cannot read address ${addr} to freeze.`);
    return;
  }

  const frozenValue = res.v;
  const t = state.type;

  const timer = setInterval(() => {
    safeWrite(addr, t, frozenValue);
  }, intervalMs);

  state.frozen.set(key, { timer, value: frozenValue, index: i });
  console.log(`[*] Frozen [${i}] ${addr} at value=${fmt(frozenValue, t)} (interval=${intervalMs}ms)`);
};

globalThis.msUnfreeze = function (index) {
  const i = index | 0;
  const addr = getAddrByIndex(i);

  if (addr === null) {
    console.log(`[!] Invalid index: ${i}`);
    return;
  }

  const key = addr.toString();

  if (!state.frozen.has(key)) {
    console.log(`[!] Address ${addr} is not frozen.`);
    return;
  }

  const entry = state.frozen.get(key);
  clearInterval(entry.timer);
  state.frozen.delete(key);
  console.log(`[*] Unfrozen [${i}] ${addr}`);
};

globalThis.msUnfreezeAll = function () {
  const count = state.frozen.size;
  for (const [key, entry] of state.frozen) {
    clearInterval(entry.timer);
  }
  state.frozen.clear();
  console.log(`[*] Unfroze ${count} address(es).`);
};

globalThis.msHelp = function () {
  console.log([
    'msHelp()',
    'msRanges([protection="rw-"])',
    'msNew(value, [type="u32"|"s32"|"f32"], [protection="rw-"])',
    'msNewRange(min, max, [type="f32"|"u32"|"s32"], [protection="rw-"], [step=4])',
    'msUse("exact"|"range")',
    'msRefine("eq"|"changed"|"unchanged"|"inc"|"dec"|"gt"|"lt", [value])',
    'msUndoRefine()',
    'msList([limit=40])',
    'msWrite(index, value)',
    'msWriteAll(value)',
    'msFreeze(index, [intervalMs=100])',
    'msUnfreeze(index)',
    'msUnfreezeAll()',
    'msClear()'
  ].join('\n'));
};
```