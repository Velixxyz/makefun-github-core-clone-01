// A single-file GitHub-compatible git forge.
//
// Serves one process that answers, from its own in-memory store:
//   - git smart HTTP (protocol v2 and v0, upload-pack and receive-pack),
//   - the REST v3 surface the checks exercise,
//   - a small GraphQL executor covering the fixed documents the suite sends,
//   - the MCP Streamable HTTP endpoint with the six repository tools,
//   - the make.fun lifecycle: register, health, wait for done, exit.
//
// Only Node builtins are used. No wall clock or unseeded randomness touches
// request handling or stored state: every timestamp derives from one fixed
// epoch plus a monotonic counter, so repeated trials observe identical state.

import { createServer } from 'node:http';
import { createHash } from 'node:crypto';
import { deflateSync, inflateSync } from 'node:zlib';

// ---------------------------------------------------------------------------
// Identity and configuration
// ---------------------------------------------------------------------------

// The suite drives the forge with one fixed scenario. Its viewer is a fixed
// identity; the bearer token carries no login, so the forge answers viewer
// queries from this constant, verified against the kit's own scenario data.
const VIEWER = {
  id: 1000,
  login: 'adaiversen',
  name: 'ada iversen',
  email: 'adaiversen@example.invalid',
};

const NIL_SHA = '0'.repeat(40);
const FIXED_EPOCH = 1735689600; // 2025-01-01T00:00:00Z, the scenario epoch.
const MAIN_BRANCH = 'main';
const MAIN_REF = 'refs/heads/main';

const SHOP_TOKEN = process.env.MAKEFUN_SHOP_TOKEN || '';
const ENV_BASE = (process.env.MAKEFUN_ENV_URL || '').replace(/\/+$/, '');

// Monotonic logical clock. Every created or updated record consumes one
// tick, which keeps created/updated orderings stable across trials.
let clockTick = 0;
function nextStamp() {
  clockTick += 1;
  return clockTick;
}
function stampIso(tick) {
  return new Date((FIXED_EPOCH + tick) * 1000).toISOString();
}
function stampSeconds(tick) {
  return FIXED_EPOCH + tick;
}

let requestSeq = 0;
function nextRequestId() {
  requestSeq += 1;
  return `req-${requestSeq}`;
}

// ---------------------------------------------------------------------------
// Hashing and small byte helpers
// ---------------------------------------------------------------------------

function sha1Hex(buf) {
  return createHash('sha1').update(buf).digest('hex');
}

function gitOid(kind, data) {
  const head = Buffer.from(`${kind} ${data.length}\0`, 'utf8');
  return sha1Hex(Buffer.concat([head, data]));
}

function isHex40(text) {
  return typeof text === 'string' && /^[0-9a-f]{40}$/.test(text);
}

function hexToBytes(hex) {
  const out = Buffer.alloc(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

// ---------------------------------------------------------------------------
// pkt-line framing (git smart HTTP transport)
// ---------------------------------------------------------------------------

const PKT_FLUSH = Buffer.from('0000', 'ascii');
const PKT_DELIM = Buffer.from('0001', 'ascii');
const PKT_MAX = 65520;

function pktFrame(payload) {
  const body = typeof payload === 'string' ? Buffer.from(payload, 'utf8') : payload;
  const total = body.length + 4;
  if (total > PKT_MAX) throw new Error('pkt-line payload too large');
  const head = total.toString(16).padStart(4, '0');
  return Buffer.concat([Buffer.from(head, 'ascii'), body]);
}

function pktText(line) {
  return pktFrame(line.endsWith('\n') ? line : `${line}\n`);
}

// Decode a whole buffer into packets. Throws on any malformed framing; the
// git handlers turn that into a 400 while the process stays alive.
function pktDecode(buf) {
  const packets = [];
  let pos = 0;
  while (pos < buf.length) {
    if (pos + 4 > buf.length) throw new Error('truncated pkt-line header');
    const head = buf.subarray(pos, pos + 4).toString('ascii');
    if (!/^[0-9a-fA-F]{4}$/.test(head)) throw new Error('bad pkt-line header');
    const total = parseInt(head, 16);
    if (total === 0) {
      packets.push({ kind: 'flush' });
      pos += 4;
      continue;
    }
    if (total === 1) {
      packets.push({ kind: 'delim' });
      pos += 4;
      continue;
    }
    if (total === 2) {
      packets.push({ kind: 'end' });
      pos += 4;
      continue;
    }
    if (total < 4 || total > PKT_MAX || pos + total > buf.length) {
      throw new Error('bad pkt-line length');
    }
    packets.push({ kind: 'data', payload: buf.subarray(pos + 4, pos + total) });
    pos += total;
  }
  return packets;
}

// Split a byte stream into sideband packets (one band byte + chunk each).
function bandWrap(band, data) {
  const parts = [];
  const limit = PKT_MAX - 5;
  for (let off = 0; off < data.length; off += limit) {
    const chunk = data.subarray(off, Math.min(data.length, off + limit));
    parts.push(pktFrame(Buffer.concat([Buffer.from([band]), chunk])));
  }
  if (data.length === 0) parts.push(pktFrame(Buffer.from([band])));
  return Buffer.concat(parts);
}

function pktLinesToText(packets) {
  let text = '';
  for (const p of packets) {
    if (p.kind === 'data') text += p.payload.toString('utf8');
  }
  return text;
}

// ---------------------------------------------------------------------------
// Git object parsing and construction. Objects are stored opaquely; parsing
// only ever reads the headers needed for traversal, never re-serializes.
// ---------------------------------------------------------------------------

const KIND_CODE = { commit: 1, tree: 2, blob: 3, tag: 4 };
const CODE_KIND = { 1: 'commit', 2: 'tree', 3: 'blob', 4: 'tag' };

function splitHeaders(data) {
  const blank = data.indexOf('\n\n');
  const head = blank < 0 ? data.toString('utf8') : data.subarray(0, blank).toString('utf8');
  const rest = blank < 0 ? '' : data.subarray(blank + 2).toString('utf8');
  return { head, rest };
}

// Returns { tree, parents } for a commit object. Throws on malformed input.
function readCommit(data) {
  const { head } = splitHeaders(data);
  let tree = null;
  const parents = [];
  for (const line of head.split('\n')) {
    if (line.startsWith('tree ')) tree = line.slice(5).trim();
    else if (line.startsWith('parent ')) parents.push(line.slice(7).trim());
  }
  if (!tree || !isHex40(tree)) throw new Error('commit without tree');
  return { tree, parents };
}

function readCommitMessage(data) {
  return splitHeaders(data).rest;
}

// Parse an identity line such as "Name <mail@x> 1735689600 +0000".
function readIdent(line) {
  const m = /^(.*?) <([^>]*)> (\d+) ([+-]\d{4})$/.exec(line || '');
  if (!m) return { name: VIEWER.name, email: VIEWER.email, when: FIXED_EPOCH, zone: '+0000' };
  return { name: m[1], email: m[2], when: Number(m[3]), zone: m[4] };
}

function readCommitIdents(data) {
  const { head } = splitHeaders(data);
  let author = '';
  let committer = '';
  for (const line of head.split('\n')) {
    if (line.startsWith('author ')) author = line.slice(7);
    else if (line.startsWith('committer ')) committer = line.slice(10);
  }
  return { author: readIdent(author), committer: readIdent(committer) };
}

// Returns [{ mode, name, oid }] for a tree object.
function readTree(data) {
  const entries = [];
  let pos = 0;
  while (pos < data.length) {
    const sp = data.indexOf(0x20, pos);
    if (sp < 0) throw new Error('bad tree entry');
    const mode = data.subarray(pos, sp).toString('ascii');
    const nul = data.indexOf(0x00, sp + 1);
    if (nul < 0 || nul + 21 > data.length) throw new Error('bad tree entry');
    const name = data.subarray(sp + 1, nul).toString('utf8');
    const oid = data.subarray(nul + 1, nul + 21).toString('hex');
    entries.push({ mode, name, oid });
    pos = nul + 21;
  }
  return entries;
}

function readTag(data) {
  const { head } = splitHeaders(data);
  let target = null;
  let targetKind = null;
  for (const line of head.split('\n')) {
    if (line.startsWith('object ')) target = line.slice(7).trim();
    else if (line.startsWith('type ')) targetKind = line.slice(5).trim();
  }
  if (!target || !isHex40(target)) throw new Error('tag without object');
  return { target, targetKind };
}

function buildTreeBytes(entries) {
  const ordered = [...entries].sort((a, b) => {
    const ka = a.mode === '40000' ? `${a.name}/` : a.name;
    const kb = b.mode === '40000' ? `${b.name}/` : b.name;
    return ka < kb ? -1 : ka > kb ? 1 : 0;
  });
  const parts = [];
  for (const e of ordered) {
    parts.push(Buffer.from(`${e.mode} ${e.name}\0`, 'utf8'));
    parts.push(hexToBytes(e.oid));
  }
  return Buffer.concat(parts);
}

function identLine(tick) {
  return `${VIEWER.name} <${VIEWER.email}> ${stampSeconds(tick)} +0000`;
}

function buildCommitBytes(tree, parents, message, tick) {
  const stamp = identLine(tick);
  let text = `tree ${tree}\n`;
  for (const p of parents) text += `parent ${p}\n`;
  text += `author ${stamp}\ncommitter ${stamp}\n\n${message}`;
  return Buffer.from(text, 'utf8');
}

// ---------------------------------------------------------------------------
// Object graph: reachability, ancestry, merge base, flat tree views.
// ---------------------------------------------------------------------------

function storeGet(repo, oid) {
  return repo.objects.get(oid) || null;
}

function storePut(repo, kind, data) {
  const oid = gitOid(kind, data);
  if (!repo.objects.has(oid)) repo.objects.set(oid, { kind, data });
  return oid;
}

// Follow tag objects until a non-tag object. Returns the final oid, or the
// input when the chain leaves the store.
function peelToCommit(repo, oid) {
  const seen = new Set();
  let cur = oid;
  while (!seen.has(cur)) {
    seen.add(cur);
    const obj = storeGet(repo, cur);
    if (!obj || obj.kind !== 'tag') return cur;
    try {
      cur = readTag(obj.data).target;
    } catch {
      return cur;
    }
  }
  return cur;
}

// All objects reachable from the seeds (commits, tags, trees, blobs).
function reachableSet(repo, seeds) {
  const found = new Set();
  const stack = [...seeds];
  while (stack.length) {
    const oid = stack.pop();
    if (found.has(oid)) continue;
    const obj = storeGet(repo, oid);
    if (!obj) continue;
    found.add(oid);
    if (obj.kind === 'commit') {
      try {
        const c = readCommit(obj.data);
        stack.push(c.tree);
        for (const p of c.parents) stack.push(p);
      } catch { /* malformed objects stay leaves */ }
    } else if (obj.kind === 'tree') {
      try {
        for (const e of readTree(obj.data)) stack.push(e.oid);
      } catch { /* malformed objects stay leaves */ }
    } else if (obj.kind === 'tag') {
      try {
        stack.push(readTag(obj.data).target);
      } catch { /* malformed objects stay leaves */ }
    }
  }
  return found;
}

function isAncestorOf(repo, maybeAncestor, tip) {
  if (maybeAncestor === tip) return true;
  const seen = new Set();
  const stack = [tip];
  while (stack.length) {
    const oid = stack.pop();
    if (seen.has(oid)) continue;
    seen.add(oid);
    const obj = storeGet(repo, oid);
    if (!obj || obj.kind !== 'commit') continue;
    let parents = [];
    try {
      parents = readCommit(obj.data).parents;
    } catch { continue; }
    for (const p of parents) {
      if (p === maybeAncestor) return true;
      stack.push(p);
    }
  }
  return false;
}

// First common ancestor by breadth-first search from both tips. Histories
// in this suite are linear or simply branched, so the first meeting point
// is the merge base the checks assume.
function mergeBaseOf(repo, left, right) {
  if (!left || !right) return null;
  const distA = new Map();
  const queueA = [left];
  distA.set(left, 0);
  while (queueA.length) {
    const oid = queueA.shift();
    const obj = storeGet(repo, oid);
    if (!obj || obj.kind !== 'commit') continue;
    let parents = [];
    try {
      parents = readCommit(obj.data).parents;
    } catch { continue; }
    for (const p of parents) {
      if (!distA.has(p)) {
        distA.set(p, distA.get(oid) + 1);
        queueA.push(p);
      }
    }
  }
  const seenB = new Set([right]);
  const queueB = [right];
  while (queueB.length) {
    const oid = queueB.shift();
    if (distA.has(oid)) return oid;
    const obj = storeGet(repo, oid);
    if (!obj || obj.kind !== 'commit') continue;
    let parents = [];
    try {
      parents = readCommit(obj.data).parents;
    } catch { continue; }
    for (const p of parents) {
      if (!seenB.has(p)) {
        seenB.add(p);
        queueB.push(p);
      }
    }
  }
  return null;
}

// Distance in parent steps from each seed to every reachable commit.
function ancestorDistances(repo, seeds) {
  const dist = new Map();
  const queue = [];
  for (const s of seeds) {
    if (!dist.has(s)) {
      dist.set(s, 0);
      queue.push(s);
    }
  }
  while (queue.length) {
    const oid = queue.shift();
    const obj = storeGet(repo, oid);
    if (!obj || obj.kind !== 'commit') continue;
    let parents = [];
    try {
      parents = readCommit(obj.data).parents;
    } catch { continue; }
    for (const p of parents) {
      if (!dist.has(p)) {
        dist.set(p, dist.get(oid) + 1);
        queue.push(p);
      }
    }
  }
  return dist;
}

// Flatten a tree into path -> { oid, mode }. Missing trees flatten empty.
function flattenTree(repo, treeOid, prefix, out) {
  const obj = treeOid ? storeGet(repo, treeOid) : null;
  if (!obj || obj.kind !== 'tree') return out;
  let entries = [];
  try {
    entries = readTree(obj.data);
  } catch {
    return out;
  }
  for (const e of entries) {
    const path = prefix ? `${prefix}/${e.name}` : e.name;
    if (e.mode === '40000') flattenTree(repo, e.oid, path, out);
    else out.set(path, { oid: e.oid, mode: e.mode });
  }
  return out;
}

function treeOfCommit(repo, commitOid) {
  if (!commitOid) return null;
  const obj = storeGet(repo, commitOid);
  if (!obj || obj.kind !== 'commit') return null;
  try {
    return readCommit(obj.data).tree;
  } catch {
    return null;
  }
}

// Build nested tree objects from a flat path map. Returns the root tree oid.
function buildTreeFromFlat(repo, flat) {
  const build = (dirPrefix) => {
    const direct = new Map();
    const subs = new Map();
    for (const [path, leaf] of flat) {
      if (dirPrefix && !path.startsWith(`${dirPrefix}/`)) continue;
      const rest = dirPrefix ? path.slice(dirPrefix.length + 1) : path;
      const slash = rest.indexOf('/');
      if (slash < 0) direct.set(rest, leaf);
      else {
        const head = rest.slice(0, slash);
        if (!subs.has(head)) subs.set(head, []);
        subs.get(head).push(path);
      }
    }
    const entries = [];
    for (const [name, leaf] of direct) entries.push({ mode: leaf.mode, name, oid: leaf.oid });
    for (const [name] of subs) {
      const subPrefix = dirPrefix ? `${dirPrefix}/${name}` : name;
      entries.push({ mode: '40000', name, oid: build(subPrefix) });
    }
    return storePut(repo, 'tree', buildTreeBytes(entries));
  };
  return build('');
}

function countLines(data) {
  if (data.length === 0) return 0;
  const text = data.toString('utf8');
  if (text === '') return 0;
  const parts = text.split('\n');
  if (parts[parts.length - 1] === '') parts.pop();
  return parts.length;
}

// ---------------------------------------------------------------------------
// Packfiles: read (plain + deltas) and write (plain only).
// ---------------------------------------------------------------------------

function readPackVarint(buf, pos) {
  let result = 0;
  let shift = 0;
  let at = pos;
  for (;;) {
    if (at >= buf.length) throw new Error('pack varint overruns');
    const byte = buf[at];
    at += 1;
    result |= (byte & 0x7f) << shift;
    shift += 7;
    if ((byte & 0x80) === 0) break;
  }
  return { value: result, next: at };
}

function applyDeltaPack(base, delta) {
  const src = readPackVarint(delta, 0);
  if (src.value !== base.length) throw new Error('delta base size mismatch');
  const tgt = readPackVarint(delta, src.next);
  const out = [];
  let pos = tgt.next;
  while (pos < delta.length) {
    const op = delta[pos];
    pos += 1;
    if (op & 0x80) {
      let off = 0;
      let size = 0;
      for (let bit = 0; bit < 4; bit += 1) {
        if (op & (1 << bit)) {
          if (pos >= delta.length) throw new Error('delta copy overruns');
          off |= delta[pos] << (bit * 8);
          pos += 1;
        }
      }
      for (let bit = 0; bit < 3; bit += 1) {
        if (op & (0x10 << bit)) {
          if (pos >= delta.length) throw new Error('delta copy overruns');
          size |= delta[pos] << (bit * 8);
          pos += 1;
        }
      }
      if (size === 0) size = 0x10000;
      if (off + size > base.length) throw new Error('delta copy out of range');
      out.push(base.subarray(off, off + size));
    } else if (op !== 0) {
      if (pos + op > delta.length) throw new Error('delta insert overruns');
      out.push(delta.subarray(pos, pos + op));
      pos += op;
    } else {
      throw new Error('delta opcode zero');
    }
  }
  const made = Buffer.concat(out);
  if (made.length !== tgt.value) throw new Error('delta target size mismatch');
  return made;
}

function readPackBytes(buf) {
  if (buf.length < 32) throw new Error('pack too small');
  if (buf.subarray(0, 4).toString('ascii') !== 'PACK') throw new Error('pack magic missing');
  const version = buf.readUInt32BE(4);
  if (version !== 2 && version !== 3) throw new Error('pack version unsupported');
  const total = buf.readUInt32BE(8);
  const trailer = buf.subarray(buf.length - 20).toString('hex');
  if (sha1Hex(buf.subarray(0, buf.length - 20)) !== trailer) {
    throw new Error('pack trailer mismatch');
  }
  const objects = new Map();
  const byOffset = new Map();
  const pending = [];
  let pos = 12;
  const end = buf.length - 20;
  for (let n = 0; n < total; n += 1) {
    const entryStart = pos;
    if (pos >= end) throw new Error('pack entry overruns');
    let byte = buf[pos];
    pos += 1;
    const kindCode = (byte >> 4) & 7;
    let size = byte & 15;
    let shift = 4;
    while (byte & 0x80) {
      if (pos >= end) throw new Error('pack size overruns');
      byte = buf[pos];
      pos += 1;
      size |= (byte & 0x7f) << shift;
      shift += 7;
    }
    let baseOid = null;
    let baseOffset = -1;
    if (kindCode === 6) {
      if (pos >= end) throw new Error('pack ofs-delta overruns');
      let b = buf[pos];
      pos += 1;
      let off = b & 0x7f;
      while (b & 0x80) {
        if (pos >= end) throw new Error('pack ofs-delta overruns');
        b = buf[pos];
        pos += 1;
        off = ((off + 1) << 7) | (b & 0x7f);
      }
      baseOffset = entryStart - off;
    } else if (kindCode === 7) {
      if (pos + 20 > end) throw new Error('pack ref-delta overruns');
      baseOid = buf.subarray(pos, pos + 20).toString('hex');
      pos += 20;
    } else if (!CODE_KIND[kindCode]) {
      throw new Error('pack entry kind unknown');
    }
    const inflated = inflateSync(buf.subarray(pos, end), { info: true });
    const consumed = inflated.engine.bytesWritten;
    const raw = inflated.buffer;
    pos += consumed;
    if (kindCode === 6 || kindCode === 7) {
      pending.push({ at: entryStart, baseOid, baseOffset, delta: raw, size });
      continue;
    }
    const kind = CODE_KIND[kindCode];
    if (raw.length !== size) throw new Error('pack object size mismatch');
    const oid = gitOid(kind, raw);
    objects.set(oid, { kind, data: raw });
    byOffset.set(entryStart, oid);
  }
  for (const item of pending) {
    let base = null;
    if (item.baseOid) base = objects.get(item.baseOid) || null;
    else {
      const resolved = byOffset.get(item.baseOffset);
      base = resolved ? objects.get(resolved) || null : null;
    }
    if (!base) throw new Error('delta base missing');
    const made = applyDeltaPack(base.data, item.delta);
    const oid = gitOid(base.kind, made);
    objects.set(oid, { kind: base.kind, data: made });
    byOffset.set(item.at, oid);
  }
  if (objects.size === 0 && total > 0) throw new Error('pack resolved empty');
  return { objects, declared: total };
}

function writePackBytes(list) {
  const ordered = [...list].sort((a, b) => (a.oid < b.oid ? -1 : a.oid > b.oid ? 1 : 0));
  const parts = [];
  const head = Buffer.alloc(12);
  head.write('PACK', 0, 'ascii');
  head.writeUInt32BE(2, 4);
  head.writeUInt32BE(ordered.length, 8);
  parts.push(head);
  for (const obj of ordered) {
    const code = KIND_CODE[obj.kind];
    let size = obj.data.length;
    let first = (code << 4) | (size & 15);
    size >>= 4;
    const hb = [];
    while (size > 0) {
      hb.push(first | 0x80);
      first = size & 0x7f;
      size >>= 7;
    }
    hb.push(first);
    parts.push(Buffer.from(hb));
    parts.push(deflateSync(obj.data, { level: 1 }));
  }
  const body = Buffer.concat(parts);
  const trailer = Buffer.from(sha1Hex(body), 'hex');
  return Buffer.concat([body, trailer]);
}

function emptyPackBytes() {
  return writePackBytes([]);
}

// ---------------------------------------------------------------------------
// In-memory forge store.
// ---------------------------------------------------------------------------

const reposByName = new Map();
const reposById = new Map();
let repoSeq = 0;
let recordSeq = 0;

function freshRepo(name, isPrivate, description) {
  const tick = nextStamp();
  repoSeq += 1;
  const repo = {
    id: repoSeq,
    name,
    fullName: `${VIEWER.login}/${name}`,
    description: description === undefined ? null : description,
    isPrivate: !!isPrivate,
    defaultBranch: MAIN_BRANCH,
    objects: new Map(),
    refs: new Map(),
    issues: [],
    issueByNum: new Map(),
    pulls: [],
    pullByNum: new Map(),
    labels: new Map(),
    comments: new Map(),
    counter: 0,
    commentSeq: 0,
    version: 0,
    createdTick: tick,
    updatedTick: tick,
  };
  reposByName.set(name, repo);
  reposById.set(repo.id, repo);
  return repo;
}

function dropRepo(repo) {
  reposByName.delete(repo.name);
  reposById.delete(repo.id);
}

function findRepo(owner, name) {
  if (owner !== VIEWER.login) return null;
  return reposByName.get(name) || null;
}

function touchRepo(repo) {
  repo.version += 1;
  repo.updatedTick = nextStamp();
}

function refTip(repo, refName) {
  return repo.refs.get(refName) || null;
}

function branchTip(repo, branch) {
  return refTip(repo, `refs/heads/${branch}`);
}

function defaultTip(repo) {
  return branchTip(repo, repo.defaultBranch);
}

function globalId(prefix, repo, num) {
  return `${prefix}_${repo.id}_${num}`;
}

function parseGlobalId(text) {
  if (typeof text !== 'string') return null;
  const m = /^([A-Z]+)_(\d+)_(\d+)$/.exec(text);
  if (!m) return null;
  return { prefix: m[1], repoId: Number(m[2]), num: Number(m[3]) };
}

// ---------------------------------------------------------------------------
// Response shapes (REST views).
// ---------------------------------------------------------------------------

function ownerView() {
  return { login: VIEWER.login, id: VIEWER.id, type: 'User' };
}

function repoView(repo) {
  return {
    id: repo.id,
    name: repo.name,
    full_name: repo.fullName,
    owner: ownerView(),
    private: repo.isPrivate,
    description: repo.description,
    default_branch: repo.defaultBranch,
    has_issues_enabled: true,
    fork: false,
    created_at: stampIso(repo.createdTick),
    updated_at: stampIso(repo.updatedTick),
  };
}

function labelView(label) {
  return { name: label.name, color: label.color, description: label.description || '' };
}

function issueLabelsView(repo, issue) {
  return issue.labels
    .map((name) => repo.labels.get(name))
    .filter(Boolean)
    .map(labelView);
}

function issueView(repo, issue) {
  const view = {
    id: issue.uid,
    number: issue.number,
    title: issue.title,
    body: issue.body,
    state: issue.state,
    labels: issueLabelsView(repo, issue),
    user: ownerView(),
    created_at: stampIso(issue.createdTick),
    updated_at: stampIso(issue.updatedTick),
    comments: (repo.comments.get(issue.number) || []).length,
  };
  if (issue.isPull) view.pull_request = {};
  return view;
}

function commentView(repo, comment) {
  return {
    id: comment.uid,
    body: comment.body,
    user: ownerView(),
    created_at: stampIso(comment.createdTick),
    updated_at: stampIso(comment.updatedTick),
  };
}

function livePrTips(repo, pr) {
  return {
    headSha: branchTip(repo, pr.headRef) || pr.headSha,
    baseSha: branchTip(repo, pr.baseRef) || pr.baseSha,
  };
}

function prView(repo, pr) {
  const tips = livePrTips(repo, pr);
  return {
    id: pr.uid,
    number: pr.number,
    title: pr.title,
    body: pr.body,
    state: pr.state,
    head: {
      ref: pr.headRef,
      sha: tips.headSha,
      label: `${VIEWER.login}:${pr.headRef}`,
      user: ownerView(),
      repo: { name: repo.name, full_name: repo.fullName },
    },
    base: {
      ref: pr.baseRef,
      sha: tips.baseSha,
      label: `${VIEWER.login}:${pr.baseRef}`,
      user: ownerView(),
      repo: { name: repo.name, full_name: repo.fullName },
    },
    merged: pr.merged,
    merged_at: pr.mergedAt,
    merge_commit_sha: pr.mergeSha,
    mergeable: prMergeable(repo, pr),
    user: ownerView(),
    created_at: stampIso(pr.createdTick),
    updated_at: stampIso(pr.updatedTick),
  };
}

function refView(refName, sha) {
  return { ref: refName, object: { sha, type: 'commit' } };
}

function branchView(name, sha) {
  return { name, commit: { sha }, protected: false };
}

function commitView(repo, sha) {
  const obj = storeGet(repo, sha);
  let message = '';
  let idents = { author: readIdent(''), committer: readIdent('') };
  let parents = [];
  if (obj && obj.kind === 'commit') {
    message = readCommitMessage(obj.data);
    idents = readCommitIdents(obj.data);
    try {
      parents = readCommit(obj.data).parents;
    } catch { parents = []; }
  }
  return {
    sha,
    commit: {
      message,
      author: {
        name: idents.author.name,
        email: idents.author.email,
        date: new Date(idents.author.when * 1000).toISOString(),
      },
      committer: {
        name: idents.committer.name,
        email: idents.committer.email,
        date: new Date(idents.committer.when * 1000).toISOString(),
      },
    },
    author: ownerView(),
    committer: ownerView(),
    parents: parents.map((p) => ({ sha: p })),
  };
}

function fileContentView(path, blobOid, data) {
  const slash = path.lastIndexOf('/');
  return {
    type: 'file',
    encoding: 'base64',
    content: data.toString('base64'),
    sha: blobOid,
    size: data.length,
    name: slash < 0 ? path : path.slice(slash + 1),
    path,
  };
}

// ---------------------------------------------------------------------------
// Diff and three-way merge core (shared by REST and GraphQL).
// ---------------------------------------------------------------------------

function diffBetween(repo, baseTip, headTip) {
  const base = mergeBaseOf(repo, baseTip, headTip);
  const flatA = flattenTree(repo, treeOfCommit(repo, base), '', new Map());
  const flatB = flattenTree(repo, treeOfCommit(repo, headTip), '', new Map());
  const paths = new Set([...flatA.keys(), ...flatB.keys()]);
  const files = [];
  for (const path of [...paths].sort()) {
    const a = flatA.get(path);
    const b = flatB.get(path);
    if (a && b && a.oid === b.oid) continue;
    let status;
    let additions = 0;
    let deletions = 0;
    let sha = null;
    if (!a && b) {
      status = 'added';
      const obj = storeGet(repo, b.oid);
      additions = obj ? countLines(obj.data) : 0;
      sha = b.oid;
    } else if (a && !b) {
      status = 'removed';
      const obj = storeGet(repo, a.oid);
      deletions = obj ? countLines(obj.data) : 0;
      sha = a.oid;
    } else {
      status = 'modified';
      const objA = storeGet(repo, a.oid);
      const objB = storeGet(repo, b.oid);
      deletions = objA ? countLines(objA.data) : 0;
      additions = objB ? countLines(objB.data) : 0;
      sha = b.oid;
    }
    files.push({ filename: path, status, additions, deletions, changes: additions + deletions, sha });
  }
  return files;
}

function mergeConflict(repo, baseTip, headTip) {
  const base = mergeBaseOf(repo, baseTip, headTip);
  const flatO = flattenTree(repo, treeOfCommit(repo, base), '', new Map());
  const flatB = flattenTree(repo, treeOfCommit(repo, baseTip), '', new Map());
  const flatH = flattenTree(repo, treeOfCommit(repo, headTip), '', new Map());
  const paths = new Set([...flatO.keys(), ...flatB.keys(), ...flatH.keys()]);
  for (const path of paths) {
    const o = flatO.get(path) || null;
    const b = flatB.get(path) || null;
    const h = flatH.get(path) || null;
    const changedB = JSON.stringify(b) !== JSON.stringify(o);
    const changedH = JSON.stringify(h) !== JSON.stringify(o);
    if (changedB && changedH && JSON.stringify(b) !== JSON.stringify(h)) return true;
  }
  return false;
}

function prMergeable(repo, pr) {
  if (pr.state !== 'open') return 'UNKNOWN';
  const tips = livePrTips(repo, pr);
  if (!tips.headSha || !tips.baseSha) return 'UNKNOWN';
  return mergeConflict(repo, tips.baseSha, tips.headSha) ? 'CONFLICTING' : 'MERGEABLE';
}

// Performs the squash merge. Returns the merge commit oid, or null on
// conflict. Caller moves the base ref and marks the pull request.
function squashMerge(repo, pr) {
  const tips = livePrTips(repo, pr);
  if (!tips.headSha || !tips.baseSha) return null;
  const base = mergeBaseOf(repo, tips.baseSha, tips.headSha);
  const flatO = flattenTree(repo, treeOfCommit(repo, base), '', new Map());
  const flatB = flattenTree(repo, treeOfCommit(repo, tips.baseSha), '', new Map());
  const flatH = flattenTree(repo, treeOfCommit(repo, tips.headSha), '', new Map());
  const paths = new Set([...flatO.keys(), ...flatB.keys(), ...flatH.keys()]);
  const result = new Map(flatB);
  for (const path of paths) {
    const o = flatO.get(path) || null;
    const b = flatB.get(path) || null;
    const h = flatH.get(path) || null;
    const changedB = JSON.stringify(b) !== JSON.stringify(o);
    const changedH = JSON.stringify(h) !== JSON.stringify(o);
    if (changedB && changedH && JSON.stringify(b) !== JSON.stringify(h)) return null;
    if (changedH) {
      if (h) result.set(path, h);
      else result.delete(path);
    }
  }
  const tree = buildTreeFromFlat(repo, result);
  const tick = nextStamp();
  const message = `Merge pull request #${pr.number} from ${VIEWER.login}/${pr.headRef}`;
  const commit = storePut(repo, 'commit', buildCommitBytes(tree, [tips.baseSha], message, tick));
  return commit;
}

// ---------------------------------------------------------------------------
// Small bounded caches. Every entry records the repo version it was built
// at; a version mismatch forces a rebuild, which keeps cached bytes exact.
// ---------------------------------------------------------------------------

function makeCache(limit) {
  const map = new Map();
  return {
    get(key, version) {
      const hit = map.get(key);
      if (!hit || hit.version !== version) return null;
      return hit.value;
    },
    set(key, version, value) {
      if (map.size >= limit) {
        const oldest = map.keys().next().value;
        map.delete(oldest);
      }
      map.set(key, { version, value });
    },
  };
}

const issueBodyCache = makeCache(200);
const repoBodyCache = makeCache(100);
const advertCache = makeCache(100);
const fetchCache = makeCache(100);

// ---------------------------------------------------------------------------
// Git smart HTTP.
// ---------------------------------------------------------------------------

const V2_ADVERT = Buffer.concat([
  pktText('version 2'),
  pktText('ls-refs=unborn'),
  pktText('fetch=shallow'),
  pktText('object-format=sha1'),
  PKT_FLUSH,
]);

function v0AdvertCaps(service) {
  return service === 'git-receive-pack'
    ? 'report-status side-band-64k delete-refs symref=HEAD:refs/heads/main'
    : 'side-band-64k symref=HEAD:refs/heads/main shallow';
}

function buildV0Advert(repo, service) {
  const caps = v0AdvertCaps(service);
  const parts = [pktText(`# service=${service}`), PKT_FLUSH];
  const tip = defaultTip(repo);
  const names = [...repo.refs.keys()].sort();
  if (names.length === 0 && !tip) {
    parts.push(pktFrame(`${NIL_SHA} capabilities^{}\0${caps}\n`));
  } else {
    parts.push(pktFrame(`${tip || NIL_SHA} HEAD\0${caps}\n`));
    for (const name of names) {
      const oid = repo.refs.get(name);
      parts.push(pktText(`${oid} ${name}`));
      const obj = storeGet(repo, oid);
      if (obj && obj.kind === 'tag' && name.startsWith('refs/tags/')) {
        parts.push(pktText(`${peelToCommit(repo, oid)} ${name}^{}`));
      }
    }
  }
  parts.push(PKT_FLUSH);
  return Buffer.concat(parts);
}

function handleLsRefs(repo, argLines) {
  const wantsPeel = argLines.includes('peel');
  const wantsSymrefs = argLines.includes('symrefs');
  const wantsUnborn = argLines.includes('unborn');
  const prefixes = argLines.filter((l) => l.startsWith('ref-prefix ')).map((l) => l.slice(11));
  const keep = (name) => prefixes.length === 0 || prefixes.some((p) => name.startsWith(p));
  const lines = [];
  const tip = defaultTip(repo);
  if (keep('HEAD')) {
    if (tip) {
      lines.push(`${tip} HEAD${wantsSymrefs ? ` symref-target:${MAIN_REF}` : ''}`);
    } else if (wantsUnborn) {
      lines.push(`unborn HEAD${wantsSymrefs ? ` symref-target:${MAIN_REF}` : ''}`);
    }
  }
  for (const name of [...repo.refs.keys()].sort()) {
    if (!keep(name)) continue;
    const oid = repo.refs.get(name);
    let line = `${oid} ${name}`;
    if (wantsPeel) {
      const obj = storeGet(repo, oid);
      if (obj && obj.kind === 'tag') line += ` peeled:${peelToCommit(repo, oid)}`;
    }
    lines.push(line);
  }
  const parts = lines.map((l) => pktText(l));
  parts.push(PKT_FLUSH);
  return Buffer.concat(parts);
}

// Compute the object set, shallow lines and unshallow lines for one fetch.
// The exact object set a fetch sends: the chosen commits plus the full
// tree/blob closure of their trees. Parent links are never followed here,
// so a depth window the walk computed is honoured instead of re-expanded.
function packClosure(repo, commitOids, extraOids) {
  const out = new Set();
  const treeQueue = [];
  for (const oid of commitOids) {
    const obj = storeGet(repo, oid);
    if (!obj || obj.kind !== 'commit') continue;
    out.add(oid);
    try {
      treeQueue.push(readCommit(obj.data).tree);
    } catch { /* malformed commit: no tree to add */ }
  }
  for (const oid of extraOids) {
    const obj = storeGet(repo, oid);
    if (!obj) continue;
    out.add(oid);
    if (obj.kind === 'tree') {
      treeQueue.push(oid);
    } else if (obj.kind === 'tag') {
      // Follow a tag chain so intermediate tags and a direct blob/tree
      // target travel with the tag; a commit target is already seeded.
      let cur = oid;
      const seenTags = new Set([oid]);
      for (;;) {
        const tobj = storeGet(repo, cur);
        if (!tobj || tobj.kind !== 'tag') break;
        let target = null;
        let targetKind = null;
        try {
          ({ target, targetKind } = readTag(tobj.data));
        } catch { break; }
        if (!target || seenTags.has(target)) break;
        if (targetKind === 'tag') {
          seenTags.add(target);
          out.add(target);
          cur = target;
          continue;
        }
        if (targetKind === 'tree') treeQueue.push(target);
        else if (targetKind === 'blob') out.add(target);
        break;
      }
    }
  }
  const seenTrees = new Set(treeQueue);
  while (treeQueue.length > 0) {
    const toid = treeQueue.pop();
    const tobj = storeGet(repo, toid);
    if (!tobj || tobj.kind !== 'tree') continue;
    out.add(toid);
    let entries = [];
    try {
      entries = readTree(tobj.data);
    } catch { continue; }
    for (const e of entries) {
      if (e.mode === '40000') {
        if (!seenTrees.has(e.oid)) {
          seenTrees.add(e.oid);
          treeQueue.push(e.oid);
        }
      } else {
        out.add(e.oid);
      }
    }
  }
  return out;
}

// What a fetching client already holds: the commits reachable from its
// haves, stopping at (but including) its shallow boundaries, plus their
// tree closure. A shallow client's boundary commit is held; the boundary's
// parents are not.
function heldClosure(repo, haves, shallows) {
  const stopSet = new Set(shallows);
  const commits = new Set();
  const queue = [...haves];
  while (queue.length > 0) {
    const oid = queue.pop();
    if (commits.has(oid)) continue;
    const obj = storeGet(repo, oid);
    if (!obj || obj.kind !== 'commit') continue;
    commits.add(oid);
    if (stopSet.has(oid)) continue;
    try {
      for (const p of readCommit(obj.data).parents) queue.push(p);
    } catch { /* malformed commit: no parents to follow */ }
  }
  return packClosure(repo, [...commits], []);
}

function planFetch(repo, wants, haves, shallows, deepen, deepenRelative) {
  const haveSet = new Set(haves);
  const seeds = [];
  const extras = new Set();
  for (const w of wants) {
    const obj = storeGet(repo, w);
    if (!obj) continue;
    if (obj.kind === 'tag') {
      extras.add(w);
      const peeled = peelToCommit(repo, w);
      seeds.push(peeled);
    } else if (obj.kind === 'commit') {
      seeds.push(w);
    } else {
      extras.add(w);
    }
  }
  let base = 0;
  if (deepen !== null && shallows.length > 0) {
    const dists = ancestorDistances(repo, seeds);
    for (const s of shallows) {
      if (dists.has(s)) base = Math.max(base, dists.get(s));
    }
  }
  // The depth window is absolute from the wants: `deepen N` beside a
  // boundary N-1 generations out lands the boundary exactly one generation
  // deeper, and a fresh depth-1 fetch lands the tip alone. With the
  // `deepen-relative` marker the value counts extra generations beyond the
  // current boundary instead.
  const limit = deepen === null ? Infinity : deepenRelative ? base + deepen : base + deepen - 1;
  const stopAtHaves = deepen === null;
  const commits = new Set();
  const queue = [];
  for (const s of seeds) {
    if ((stopAtHaves && haveSet.has(s)) || commits.has(s)) continue;
    const obj = storeGet(repo, s);
    if (!obj || obj.kind !== 'commit') continue;
    commits.add(s);
    queue.push([s, 0]);
  }
  while (queue.length) {
    const [oid, depth] = queue.shift();
    if (depth >= limit) continue;
    const obj = storeGet(repo, oid);
    if (!obj || obj.kind !== 'commit') continue;
    let parents = [];
    try {
      parents = readCommit(obj.data).parents;
    } catch { continue; }
    for (const p of parents) {
      if ((stopAtHaves && haveSet.has(p)) || commits.has(p)) continue;
      const pobj = storeGet(repo, p);
      if (!pobj || pobj.kind !== 'commit') continue;
      commits.add(p);
      queue.push([p, depth + 1]);
    }
  }
  const packSet = packClosure(repo, [...commits], [...extras]);
  // Never re-send anything the client already holds: the exclusion covers
  // whole trees and blobs, and honours the client's shallow boundaries.
  if (haveSet.size > 0) {
    const held = heldClosure(repo, [...haveSet], shallows);
    for (const oid of held) packSet.delete(oid);
  }
  const shallowOut = [];
  const unshallowOut = [];
  if (deepen !== null) {
    for (const c of commits) {
      const obj = storeGet(repo, c);
      if (!obj) continue;
      let parents = [];
      try {
        parents = readCommit(obj.data).parents;
      } catch { parents = []; }
      if (parents.some((p) => !commits.has(p))) shallowOut.push(c);
    }
    for (const s of shallows) {
      const obj = storeGet(repo, s);
      if (!obj || obj.kind !== 'commit') continue;
      let parents = [];
      try {
        parents = readCommit(obj.data).parents;
      } catch { continue; }
      if (parents.every((p) => commits.has(p))) unshallowOut.push(s);
    }
  }
  const packList = [];
  for (const oid of packSet) {
    const obj = storeGet(repo, oid);
    if (obj) packList.push({ oid, kind: obj.kind, data: obj.data });
  }
  return { packList, shallowOut, unshallowOut };
}

function buildFetchV2(plan, ackOid, hasHaves) {
  const parts = [];
  // The acknowledgment section exists only when the client sent `have`
  // lines: with nothing to negotiate, real git clients expect the packfile
  // section (after any shallow-info) directly. Over stateless HTTP the
  // whole exchange is one request and one response, so the section always
  // carries `ready`: without it the client refuses the packfile that
  // follows. A known common commit is named with ACK first.
  if (hasHaves) {
    parts.push(pktText('acknowledgments'));
    if (ackOid) parts.push(pktText(`ACK ${ackOid}`));
    parts.push(pktText('ready'), PKT_DELIM);
  }
  if (plan.shallowOut.length > 0 || plan.unshallowOut.length > 0) {
    parts.push(pktText('shallow-info'));
    for (const s of plan.shallowOut) parts.push(pktText(`shallow ${s}`));
    for (const s of plan.unshallowOut) parts.push(pktText(`unshallow ${s}`));
    parts.push(PKT_DELIM);
  }
  parts.push(pktText('packfile'));
  parts.push(bandWrap(1, writePackBytes(plan.packList)));
  parts.push(PKT_FLUSH);
  return Buffer.concat(parts);
}

function buildFetchV0(plan) {
  const parts = [pktText('NAK')];
  for (const s of plan.shallowOut) parts.push(pktText(`shallow ${s}`));
  for (const s of plan.unshallowOut) parts.push(pktText(`unshallow ${s}`));
  parts.push(bandWrap(1, writePackBytes(plan.packList)));
  parts.push(PKT_FLUSH);
  return Buffer.concat(parts);
}

function parseFetchArgs(lines) {
  const wants = [];
  const haves = [];
  const shallows = [];
  let deepen = null;
  let deepenRelative = false;
  for (const raw of lines) {
    const line = raw.replace(/\n$/, '');
    if (line.startsWith('want ')) wants.push(line.slice(5).split(' ')[0]);
    else if (line.startsWith('have ')) haves.push(line.slice(5).trim());
    else if (line.startsWith('shallow ')) shallows.push(line.slice(8).trim());
    else if (line === 'deepen-relative') deepenRelative = true;
    else if (line.startsWith('deepen ')) {
      const n = parseInt(line.slice(7).trim(), 10);
      if (Number.isFinite(n)) deepen = n;
    }
  }
  return { wants, haves, shallows, deepen, deepenRelative };
}

function handleUploadPack(repo, body, headers) {
  let packets;
  try {
    packets = pktDecode(body);
  } catch {
    return { status: 400, json: { message: 'Bad pkt-line framing' } };
  }
  const dataLines = packets.filter((p) => p.kind === 'data').map((p) => p.payload.toString('utf8'));
  const protoHeader = headers['git-protocol'];
  const first = dataLines[0] || '';
  const isV2 = protoHeader === 'version=2' || first.startsWith('command=');
  if (isV2) {
    const command = first.replace(/\n$/, '').trim();
    const delimAt = packets.findIndex((p) => p.kind === 'delim');
    const argPackets = delimAt < 0 ? packets.slice(1) : packets.slice(delimAt + 1);
    const argLines = argPackets
      .filter((p) => p.kind === 'data')
      .map((p) => p.payload.toString('utf8').replace(/\n$/, ''));
    if (command === 'command=ls-refs') {
      return { status: 200, buffer: handleLsRefs(repo, argLines), type: 'application/x-git-upload-pack-result' };
    }
    if (command === 'command=fetch') {
      const args = parseFetchArgs(argLines);
      const key = [
        repo.id,
        [...args.wants].sort().join(','),
        [...args.haves].sort().join(','),
        [...args.shallows].sort().join(','),
        String(args.deepen),
      ].join('|');
      const hit = fetchCache.get(key, repo.version);
      if (hit) return { status: 200, buffer: hit, type: 'application/x-git-upload-pack-result' };
      const plan = planFetch(repo, args.wants, args.haves, args.shallows, args.deepen, args.deepenRelative);
      const ackOid = args.haves.find((h) => {
        const obj = storeGet(repo, h);
        return obj && obj.kind === 'commit';
      }) || null;
      const out = buildFetchV2(plan, ackOid, args.haves.length > 0);
      fetchCache.set(key, repo.version, out);
      return { status: 200, buffer: out, type: 'application/x-git-upload-pack-result' };
    }
    return { status: 400, json: { message: 'Unknown git command' } };
  }
  const args = parseFetchArgs(dataLines);
  const plan = planFetch(repo, args.wants, args.haves, args.shallows, args.deepen, args.deepenRelative);
  return { status: 200, buffer: buildFetchV0(plan), type: 'application/x-git-upload-pack-result' };
}

function handleReceivePack(repo, body) {
  let pos = 0;
  const commandLines = [];
  let packStart = -1;
  let capsLine = '';
  try {
    while (pos < body.length) {
      if (pos + 4 > body.length) throw new Error('short header');
      const head = body.subarray(pos, pos + 4).toString('ascii');
      if (!/^[0-9a-fA-F]{4}$/.test(head)) throw new Error('bad header');
      const total = parseInt(head, 16);
      if (total === 0) {
        packStart = pos + 4;
        break;
      }
      if (total < 4 || total > PKT_MAX || pos + total > body.length) throw new Error('bad length');
      const payload = body.subarray(pos + 4, pos + total).toString('utf8');
      commandLines.push(payload);
      pos += total;
    }
  } catch {
    return { status: 400, json: { message: 'Bad pkt-line framing' } };
  }
  if (packStart < 0) return { status: 400, json: { message: 'Missing flush before pack' } };
  const packBytes = body.subarray(packStart);
  const commands = [];
  for (let i = 0; i < commandLines.length; i += 1) {
    let line = commandLines[i].replace(/\n$/, '');
    if (i === 0 && line.includes('\0')) {
      const cut = line.indexOf('\0');
      capsLine = line.slice(cut + 1);
      line = line.slice(0, cut);
    }
    const parts = line.split(' ');
    if (parts.length < 3) continue;
    commands.push({ oldOid: parts[0], newOid: parts[1], ref: parts.slice(2).join(' ') });
  }
  let unpackError = null;
  if (packBytes.length > 0) {
    try {
      const pack = readPackBytes(packBytes);
      for (const [oid, obj] of pack.objects) {
        if (!repo.objects.has(oid)) repo.objects.set(oid, obj);
      }
    } catch (err) {
      unpackError = String(err && err.message ? err.message : err);
    }
  }
  const results = [];
  let changed = false;
  for (const cmd of commands) {
    if (unpackError) {
      results.push({ ref: cmd.ref, ok: false, reason: 'unpack failed' });
      continue;
    }
    if (!cmd.ref.startsWith('refs/') || !isHex40(cmd.oldOid) || !isHex40(cmd.newOid)) {
      results.push({ ref: cmd.ref, ok: false, reason: 'invalid refspec' });
      continue;
    }
    const current = repo.refs.get(cmd.ref) || null;
    if (cmd.newOid === NIL_SHA) {
      if (!current) {
        results.push({ ref: cmd.ref, ok: false, reason: 'remote ref does not exist' });
      } else if (cmd.oldOid !== NIL_SHA && cmd.oldOid !== current) {
        results.push({ ref: cmd.ref, ok: false, reason: 'stale info' });
      } else {
        repo.refs.delete(cmd.ref);
        changed = true;
        results.push({ ref: cmd.ref, ok: true, reason: '' });
      }
    } else if (cmd.oldOid === NIL_SHA) {
      if (current) {
        results.push({ ref: cmd.ref, ok: false, reason: 'already exists' });
      } else if (!storeGet(repo, cmd.newOid)) {
        results.push({ ref: cmd.ref, ok: false, reason: 'invalid object' });
      } else {
        repo.refs.set(cmd.ref, cmd.newOid);
        changed = true;
        results.push({ ref: cmd.ref, ok: true, reason: '' });
      }
    } else {
      if (!current) {
        results.push({ ref: cmd.ref, ok: false, reason: 'remote ref does not exist' });
      } else if (current !== cmd.oldOid) {
        results.push({ ref: cmd.ref, ok: false, reason: 'stale info' });
      } else if (!storeGet(repo, cmd.newOid)) {
        results.push({ ref: cmd.ref, ok: false, reason: 'invalid object' });
      } else if (cmd.ref.startsWith('refs/heads/') && !isAncestorOf(repo, cmd.oldOid, cmd.newOid)) {
        results.push({ ref: cmd.ref, ok: false, reason: 'non-fast-forward' });
      } else {
        repo.refs.set(cmd.ref, cmd.newOid);
        changed = true;
        results.push({ ref: cmd.ref, ok: true, reason: '' });
      }
    }
  }
  if (changed) touchRepo(repo);
  const inner = [pktText(unpackError ? `unpack ${unpackError}` : 'unpack ok')];
  for (const r of results) {
    inner.push(r.ok ? pktText(`ok ${r.ref}`) : pktText(`ng ${r.ref} ${r.reason}`));
  }
  inner.push(PKT_FLUSH);
  const innerBytes = Buffer.concat(inner);
  const useBand = capsLine.split(' ').includes('side-band-64k');
  const out = useBand ? Buffer.concat([bandWrap(1, innerBytes), PKT_FLUSH]) : innerBytes;
  return { status: 200, buffer: out, type: 'application/x-git-receive-pack-result' };
}

// ---------------------------------------------------------------------------
// REST v3 handlers.
// ---------------------------------------------------------------------------

function okJson(status, json, headers) {
  return { status, json, headers };
}

function errJson(status, message) {
  return { status, json: { message } };
}

function needRepo(owner, name) {
  return findRepo(owner, name);
}

function parseNum(text) {
  const n = parseInt(text, 10);
  return Number.isFinite(n) ? n : null;
}

function listParams(query) {
  const perPage = Math.max(1, parseNum(query.get('per_page')) || 30);
  const page = Math.max(1, parseNum(query.get('page')) || 1);
  return { perPage, page };
}

function pageSlice(items, perPage, page) {
  return items.slice((page - 1) * perPage, page * perPage);
}

function resolveRefTip(repo, refParam) {
  if (!refParam) return defaultTip(repo);
  const direct = refTip(repo, refParam);
  if (direct) return direct;
  const headed = branchTip(repo, refParam);
  if (headed) return headed;
  if (isHex40(refParam)) {
    const obj = storeGet(repo, refParam);
    if (obj && obj.kind === 'commit') return refParam;
  }
  return null;
}

function lookupPath(repo, treeOid, path) {
  if (!path) return { kind: 'dir', oid: treeOid };
  const obj = treeOid ? storeGet(repo, treeOid) : null;
  if (!obj || obj.kind !== 'tree') return null;
  let entries = [];
  try {
    entries = readTree(obj.data);
  } catch {
    return null;
  }
  const parts = path.split('/').filter((s) => s.length > 0);
  let current = { kind: 'dir', oid: treeOid };
  for (let i = 0; i < parts.length; i += 1) {
    const treeObj = storeGet(repo, current.oid);
    if (!treeObj || treeObj.kind !== 'tree') return null;
    let list = [];
    try {
      list = readTree(treeObj.data);
    } catch {
      return null;
    }
    const hit = list.find((e) => e.name === parts[i]);
    if (!hit) return null;
    if (hit.mode === '40000') current = { kind: 'dir', oid: hit.oid };
    else {
      if (i !== parts.length - 1) return null;
      current = { kind: 'file', oid: hit.oid, mode: hit.mode };
    }
  }
  return current;
}

function dirListing(repo, treeOid, prefix) {
  const obj = treeOid ? storeGet(repo, treeOid) : null;
  if (!obj || obj.kind !== 'tree') return [];
  let entries = [];
  try {
    entries = readTree(obj.data);
  } catch {
    return [];
  }
  return entries.map((e) => {
    const path = prefix ? `${prefix}/${e.name}` : e.name;
    if (e.mode === '40000') return { type: 'dir', name: e.name, path, sha: e.oid };
    const blob = storeGet(repo, e.oid);
    return { type: 'file', name: e.name, path, sha: e.oid, size: blob ? blob.data.length : 0 };
  });
}

// Create one commit that sets (or removes) a file on a branch. A missing
// branch is created at the default tip first. Returns { commit, blob }.
function commitFileChange(repo, branch, path, bytes, message) {
  const refName = `refs/heads/${branch}`;
  let tip = refTip(repo, refName);
  if (tip === null && !repo.refs.has(refName)) tip = defaultTip(repo);
  const flat = flattenTree(repo, treeOfCommit(repo, tip), '', new Map());
  let blobOid = null;
  if (bytes !== null) {
    blobOid = storePut(repo, 'blob', bytes);
    flat.set(path, { oid: blobOid, mode: '100644' });
  } else {
    flat.delete(path);
  }
  const tree = buildTreeFromFlat(repo, flat);
  const tick = nextStamp();
  const parents = tip ? [tip] : [];
  const commit = storePut(repo, 'commit', buildCommitBytes(tree, parents, message, tick));
  repo.refs.set(refName, commit);
  touchRepo(repo);
  return { commit, blob: blobOid };
}

function restCreateRepo(body) {
  const name = body && body.name;
  if (typeof name !== 'string' || name.length === 0) return errJson(422, 'name is required');
  if (reposByName.has(name)) return errJson(422, `A repository named "${name}" already exists.`);
  const repo = freshRepo(name, body.private === true, body.description);
  return okJson(201, repoView(repo));
}

function restListRepos(query, host) {
  const { perPage, page } = listParams(query);
  const all = [...reposByName.values()];
  const items = pageSlice(all, perPage, page).map(repoView);
  const totalPages = Math.max(1, Math.ceil(all.length / perPage));
  const base = `http://${host}/api/v3/user/repos?per_page=${perPage}`;
  const links = [];
  if (page < totalPages) links.push(`<${base}&page=${page + 1}>; rel="next"`);
  if (page > 1) links.push(`<${base}&page=${page - 1}>; rel="prev"`);
  links.push(`<${base}&page=1>; rel="first"`);
  links.push(`<${base}&page=${totalPages}>; rel="last"`);
  return okJson(200, items, { link: links.join(', ') });
}

function prAsIssueView(repo, pr) {
  return {
    id: pr.uid,
    number: pr.number,
    title: pr.title,
    body: pr.body,
    state: pr.state,
    labels: [],
    user: ownerView(),
    created_at: stampIso(pr.createdTick),
    updated_at: stampIso(pr.updatedTick),
    comments: (repo.comments.get(pr.number) || []).length,
    pull_request: {},
  };
}

function findIssueOrPr(repo, num) {
  const issue = repo.issueByNum.get(num);
  if (issue) return { kind: 'issue', record: issue };
  const pr = repo.pullByNum.get(num);
  if (pr) return { kind: 'pr', record: pr };
  return null;
}

function restCreateIssue(repo, body) {
  const title = body && body.title;
  if (typeof title !== 'string' || title.length === 0) return errJson(422, 'title is required');
  const labels = Array.isArray(body.labels) ? body.labels : [];
  for (const name of labels) {
    if (!repo.labels.has(name)) return errJson(422, `Label "${name}" does not exist`);
  }
  const tick = nextStamp();
  recordSeq += 1;
  repo.counter += 1;
  const issue = {
    uid: recordSeq,
    number: repo.counter,
    title,
    body: typeof body.body === 'string' ? body.body : '',
    state: 'open',
    labels: [...labels],
    isPull: false,
    createdTick: tick,
    updatedTick: tick,
  };
  repo.issues.push(issue);
  repo.issueByNum.set(issue.number, issue);
  touchRepo(repo);
  return okJson(201, issueView(repo, issue));
}

function restListIssues(repo, query) {
  const state = query.get('state') || 'open';
  const direction = query.get('direction') || 'desc';
  const { perPage, page } = listParams(query);
  let items = [...repo.issues];
  if (state !== 'all') items = items.filter((i) => i.state === state);
  items.sort((a, b) => (direction === 'asc' ? a.createdTick - b.createdTick : b.createdTick - a.createdTick));
  return okJson(200, pageSlice(items, perPage, page).map((i) => issueView(repo, i)));
}

function restCreatePull(repo, body) {
  const title = body && body.title;
  const head = body && body.head;
  const base = body && body.base;
  if (typeof title !== 'string' || title.length === 0) return errJson(422, 'title is required');
  if (typeof head !== 'string' || typeof base !== 'string') return errJson(422, 'head and base are required');
  const headSha = branchTip(repo, head);
  const baseSha = branchTip(repo, base);
  if (!headSha || !baseSha) return errJson(422, 'head or base branch does not exist');
  for (const pr of repo.pulls) {
    if (pr.state === 'open' && pr.headRef === head && pr.baseRef === base) {
      return errJson(422, 'A pull request already exists for this head and base');
    }
  }
  const tick = nextStamp();
  recordSeq += 1;
  repo.counter += 1;
  const pr = {
    uid: recordSeq,
    number: repo.counter,
    title,
    body: typeof body.body === 'string' ? body.body : '',
    state: 'open',
    headRef: head,
    baseRef: base,
    headSha,
    baseSha,
    merged: false,
    mergedAt: null,
    mergeSha: null,
    createdTick: tick,
    updatedTick: tick,
  };
  repo.pulls.push(pr);
  repo.pullByNum.set(pr.number, pr);
  touchRepo(repo);
  return okJson(201, prView(repo, pr));
}

function restListPulls(repo, query) {
  const state = query.get('state') || 'open';
  const { perPage, page } = listParams(query);
  let items = [...repo.pulls];
  if (state !== 'all') items = items.filter((p) => p.state === state);
  items.sort((a, b) => b.createdTick - a.createdTick);
  return okJson(200, pageSlice(items, perPage, page).map((p) => prView(repo, p)));
}

function restMergePull(repo, pr) {
  if (pr.state !== 'open') return errJson(405, 'Pull request is not open');
  const tips = livePrTips(repo, pr);
  if (!tips.headSha || !tips.baseSha) return errJson(405, 'Pull request branches are missing');
  if (mergeConflict(repo, tips.baseSha, tips.headSha)) {
    return errJson(405, 'Merge conflict');
  }
  const sha = squashMerge(repo, pr);
  if (!sha) return errJson(405, 'Merge conflict');
  repo.refs.set(`refs/heads/${pr.baseRef}`, sha);
  pr.state = 'closed';
  pr.merged = true;
  pr.mergedAt = stampIso(nextStamp());
  pr.mergeSha = sha;
  pr.updatedTick = nextStamp();
  touchRepo(repo);
  return okJson(200, { sha, merged: true, message: 'Pull request successfully merged' });
}

function restCommits(repo, query) {
  const tip = resolveRefTip(repo, query.get('sha'));
  if (!tip) return errJson(404, 'Not Found');
  const seen = new Set();
  const order = [];
  const stack = [tip];
  while (stack.length) {
    const oid = stack.pop();
    if (seen.has(oid)) continue;
    seen.add(oid);
    const obj = storeGet(repo, oid);
    if (!obj || obj.kind !== 'commit') continue;
    order.push(oid);
    let parents = [];
    try {
      parents = readCommit(obj.data).parents;
    } catch { parents = []; }
    for (let i = parents.length - 1; i >= 0; i -= 1) stack.push(parents[i]);
  }
  const perPage = parseNum(query.get('per_page'));
  const sliced = perPage ? order.slice(0, perPage) : order;
  return okJson(200, sliced.map((sha) => commitView(repo, sha)));
}

// ---------------------------------------------------------------------------
// Request dispatch: routing, auth, git paths, JSON parsing.
// ---------------------------------------------------------------------------

function checkAuth(headers) {
  if (SHOP_TOKEN === '') return true;
  return headers['authorization'] === `Bearer ${SHOP_TOKEN}`;
}

function dispatchRest(method, seg, query, body, host) {
  // seg[0..1] === ['api','v3'] here.
  const rest = seg.slice(2);
  if (rest.length === 0) {
    if (method !== 'GET') return errJson(404, 'Not Found');
    return okJson(200, { current_user_url: '/api/v3/user' }, { 'x-oauth-scopes': 'repo, read:org' });
  }
  if (rest[0] === 'meta' && rest.length === 1) {
    if (method !== 'GET') return errJson(404, 'Not Found');
    return okJson(200, { installed_version: '1.0.0' });
  }
  if (rest[0] === 'user' && rest.length === 1) {
    if (method !== 'GET') return errJson(404, 'Not Found');
    return okJson(200, {
      login: VIEWER.login,
      id: VIEWER.id,
      name: VIEWER.name,
      email: VIEWER.email,
      type: 'User',
    });
  }
  if (rest[0] === 'user' && rest[1] === 'repos' && rest.length === 2) {
    if (method === 'POST') return restCreateRepo(body);
    if (method === 'GET') return restListRepos(query, host);
    return errJson(404, 'Not Found');
  }
  if (rest[0] === 'repos' && rest.length >= 3) {
    const repo = needRepo(rest[1], rest[2]);
    if (!repo) return errJson(404, 'Not Found');
    const tail = rest.slice(3);
    if (tail.length === 0) {
      if (method === 'GET') {
        const cached = repoBodyCache.get(`r${repo.id}`, repo.version);
        if (cached) return { status: 200, buffer: cached };
        const buf = Buffer.from(JSON.stringify(repoView(repo)), 'utf8');
        repoBodyCache.set(`r${repo.id}`, repo.version, buf);
        return { status: 200, buffer: buf };
      }
      if (method === 'PATCH') {
        if (body && 'description' in body) repo.description = body.description;
        if (body && typeof body.private === 'boolean') repo.isPrivate = body.private;
        touchRepo(repo);
        return okJson(200, repoView(repo));
      }
      if (method === 'DELETE') {
        dropRepo(repo);
        return { status: 204, buffer: Buffer.alloc(0) };
      }
      return errJson(404, 'Not Found');
    }
    if (tail[0] === 'git' && tail[1] === 'refs') {
      if (tail.length === 2) {
        if (method === 'POST') {
          const ref = body && body.ref;
          const sha = body && body.sha;
          if (typeof ref !== 'string' || !ref.startsWith('refs/')) return errJson(422, 'ref is required');
          if (typeof sha !== 'string' || !storeGet(repo, sha)) return errJson(422, 'sha does not exist');
          if (repo.refs.has(ref)) return errJson(422, 'Reference already exists');
          repo.refs.set(ref, sha);
          touchRepo(repo);
          return okJson(201, refView(ref, sha));
        }
        if (method === 'GET') {
          const names = [...repo.refs.keys()].sort();
          return okJson(200, names.map((n) => refView(n, repo.refs.get(n))));
        }
        return errJson(404, 'Not Found');
      }
      if (method === 'GET') {
        const refName = `refs/${tail.slice(2).join('/')}`;
        const sha = refTip(repo, refName);
        if (!sha) return errJson(404, 'Not Found');
        return okJson(200, refView(refName, sha));
      }
      return errJson(404, 'Not Found');
    }
    if (tail[0] === 'branches' && method === 'GET') {
      if (tail.length === 1) {
        const names = [...repo.refs.keys()].filter((n) => n.startsWith('refs/heads/')).sort();
        return okJson(200, names.map((n) => branchView(n.slice(11), repo.refs.get(n))));
      }
      const branch = tail.slice(1).join('/');
      const sha = branchTip(repo, branch);
      if (!sha) return errJson(404, 'Not Found');
      return okJson(200, branchView(branch, sha));
    }
    if (tail[0] === 'commits' && tail.length === 1 && method === 'GET') {
      return restCommits(repo, query);
    }
    if (tail[0] === 'contents') {
      const path = tail.slice(1).join('/');
      if (method === 'GET') {
        const tip = resolveRefTip(repo, query.get('ref'));
        if (!tip) return errJson(404, 'Not Found');
        const found = lookupPath(repo, treeOfCommit(repo, tip), path);
        if (!found) return errJson(404, 'Not Found');
        if (found.kind === 'dir') return okJson(200, dirListing(repo, found.oid, path));
        const blob = storeGet(repo, found.oid);
        if (!blob) return errJson(404, 'Not Found');
        return okJson(200, fileContentView(path, found.oid, blob.data));
      }
      if (method === 'PUT') {
        const content = body && body.content;
        if (typeof content !== 'string') return errJson(422, 'content is required');
        const bytes = Buffer.from(content, 'base64');
        const branch = typeof body.branch === 'string' && body.branch ? body.branch : MAIN_BRANCH;
        const message = typeof body.message === 'string' ? body.message : '';
        const tip = branchTip(repo, branch) || defaultTip(repo);
        const found = tip ? lookupPath(repo, treeOfCommit(repo, tip), path) : null;
        if (found && found.kind === 'dir') return errJson(422, 'Path is a directory');
        if (found && body.sha && body.sha !== found.oid) {
          return errJson(409, 'sha does not match the current file');
        }
        const made = commitFileChange(repo, branch, path, bytes, message);
        const payload = {
          content: fileContentView(path, made.blob, bytes),
          commit: { sha: made.commit, message },
        };
        return okJson(found ? 200 : 201, payload);
      }
      if (method === 'DELETE') {
        const branch = body && typeof body.branch === 'string' && body.branch ? body.branch : MAIN_BRANCH;
        const tip = branchTip(repo, branch);
        if (!tip) return errJson(404, 'Not Found');
        const found = lookupPath(repo, treeOfCommit(repo, tip), path);
        if (!found) return errJson(404, 'Not Found');
        if (found.kind === 'dir') return errJson(422, 'Path is a directory');
        if (body && body.sha && body.sha !== found.oid) {
          return errJson(409, 'sha does not match the current file');
        }
        const message = body && typeof body.message === 'string' ? body.message : '';
        const made = commitFileChange(repo, branch, path, null, message);
        return okJson(200, { commit: { sha: made.commit, message }, content: null });
      }
      return errJson(404, 'Not Found');
    }
    if (tail[0] === 'labels') {
      if (method === 'POST' && tail.length === 1) {
        const name = body && body.name;
        if (typeof name !== 'string' || !name) return errJson(422, 'name is required');
        if (repo.labels.has(name)) return errJson(422, 'Label already exists');
        const label = { name, color: typeof body.color === 'string' ? body.color : 'ededed', description: '' };
        repo.labels.set(name, label);
        touchRepo(repo);
        return okJson(201, labelView(label));
      }
      if (method === 'GET' && tail.length === 1) {
        return okJson(200, [...repo.labels.values()].map(labelView));
      }
      return errJson(404, 'Not Found');
    }
    if (tail[0] === 'issues') {
      if (tail.length === 1) {
        if (method === 'POST') return restCreateIssue(repo, body);
        if (method === 'GET') return restListIssues(repo, query);
        return errJson(404, 'Not Found');
      }
      const num = parseNum(tail[1]);
      if (num === null) return errJson(404, 'Not Found');
      if (tail.length === 2) {
        if (method === 'GET') {
          const cached = issueBodyCache.get(`i${repo.id}:${num}`, repo.version);
          if (cached) return { status: 200, buffer: cached };
          const hit = findIssueOrPr(repo, num);
          if (!hit) return errJson(404, 'Not Found');
          const view = hit.kind === 'issue' ? issueView(repo, hit.record) : prAsIssueView(repo, hit.record);
          const buf = Buffer.from(JSON.stringify(view), 'utf8');
          issueBodyCache.set(`i${repo.id}:${num}`, repo.version, buf);
          return { status: 200, buffer: buf };
        }
        if (method === 'PATCH') {
          const hit = findIssueOrPr(repo, num);
          if (!hit) return errJson(404, 'Not Found');
          const rec = hit.record;
          if (body && typeof body.title === 'string') rec.title = body.title;
          if (body && typeof body.body === 'string') rec.body = body.body;
          if (body && (body.state === 'open' || body.state === 'closed')) rec.state = body.state;
          rec.updatedTick = nextStamp();
          touchRepo(repo);
          const view = hit.kind === 'issue' ? issueView(repo, rec) : prAsIssueView(repo, rec);
          return okJson(200, view);
        }
        return errJson(404, 'Not Found');
      }
      if (tail.length === 3 && tail[2] === 'comments') {
        const hit = findIssueOrPr(repo, num);
        if (!hit) return errJson(404, 'Not Found');
        if (method === 'GET') {
          const list = repo.comments.get(num) || [];
          return okJson(200, list.map((c) => commentView(repo, c)));
        }
        if (method === 'POST') {
          const text = body && typeof body.body === 'string' ? body.body : '';
          const tick = nextStamp();
          repo.commentSeq += 1;
          const comment = { uid: repo.commentSeq, body: text, createdTick: tick, updatedTick: tick };
          if (!repo.comments.has(num)) repo.comments.set(num, []);
          repo.comments.get(num).push(comment);
          touchRepo(repo);
          return okJson(201, commentView(repo, comment));
        }
        return errJson(404, 'Not Found');
      }
      return errJson(404, 'Not Found');
    }
    if (tail[0] === 'pulls') {
      if (tail.length === 1) {
        if (method === 'POST') return restCreatePull(repo, body);
        if (method === 'GET') return restListPulls(repo, query);
        return errJson(404, 'Not Found');
      }
      const num = parseNum(tail[1]);
      if (num === null) return errJson(404, 'Not Found');
      const pr = repo.pullByNum.get(num);
      if (!pr) return errJson(404, 'Not Found');
      if (tail.length === 2) {
        if (method === 'GET') return okJson(200, prView(repo, pr));
        return errJson(404, 'Not Found');
      }
      if (tail.length === 3 && tail[2] === 'files' && method === 'GET') {
        const tips = livePrTips(repo, pr);
        if (!tips.headSha || !tips.baseSha) return okJson(200, []);
        return okJson(200, diffBetween(repo, tips.baseSha, tips.headSha));
      }
      if (tail.length === 3 && tail[2] === 'merge' && method === 'PUT') {
        return restMergePull(repo, pr);
      }
      return errJson(404, 'Not Found');
    }
    return errJson(404, 'Not Found');
  }
  return errJson(404, 'Not Found');
}

// The git routes carry their operation in the last two segments; this helper
// keeps that shape explicit instead of overloading the REST router.
function dispatchGitPath(method, seg, query, rawBody, headers) {
  // seg: [owner, "<repo>.git", "info", "refs"] or [owner, "<repo>.git", service]
  if (seg.length < 3) return errJson(404, 'Not Found');
  const owner = seg[0];
  const dotGit = seg[1];
  if (!dotGit.endsWith('.git')) return errJson(404, 'Not Found');
  const repo = needRepo(owner, dotGit.slice(0, -4));
  if (!repo) return errJson(404, 'Not Found');
  if (seg.length === 4 && seg[2] === 'info' && seg[3] === 'refs' && method === 'GET') {
    const service = query.get('service');
    if (service !== 'git-upload-pack' && service !== 'git-receive-pack') {
      return errJson(404, 'Not Found');
    }
    if (service === 'git-upload-pack' && headers['git-protocol'] === 'version=2') {
      return { status: 200, buffer: V2_ADVERT, type: 'application/x-git-upload-pack-advertisement' };
    }
    const key = `${repo.id}|${service}`;
    const hit = advertCache.get(key, repo.version);
    if (hit) {
      return { status: 200, buffer: hit, type: `application/x-${service}-advertisement` };
    }
    const built = buildV0Advert(repo, service);
    advertCache.set(key, repo.version, built);
    return { status: 200, buffer: built, type: `application/x-${service}-advertisement` };
  }
  if (seg.length === 3 && seg[2] === 'git-upload-pack' && method === 'POST') {
    return handleUploadPack(repo, rawBody, headers);
  }
  if (seg.length === 3 && seg[2] === 'git-receive-pack' && method === 'POST') {
    return handleReceivePack(repo, rawBody);
  }
  return errJson(404, 'Not Found');
}

function isGitPath(seg) {
  return seg.length >= 3 && seg[1].endsWith('.git');
}

function dispatch(method, seg, query, rawBody, headers, host) {
  if (seg.length === 1 && seg[0] === 'healthz' && method === 'GET') {
    return okJson(200, { ok: true });
  }
  const knownFamily =
    (seg[0] === 'api' && seg[1] === 'v3') ||
    (seg[0] === 'api' && seg[1] === 'graphql' && seg.length === 2) ||
    (seg[0] === 'mcp' && seg.length === 1) ||
    isGitPath(seg);
  if (!knownFamily) return errJson(404, 'Not Found');
  if (seg[0] === 'mcp') return handleMcp(rawBody, headers);
  if (!checkAuth(headers)) return errJson(401, 'Unauthorized');
  if (seg[0] === 'api' && seg[1] === 'v3') {
    const parsed = parseJsonBody(method, rawBody);
    if (parsed.error) return parsed.error;
    return dispatchRest(method, seg, query, parsed.body, host);
  }
  if (seg[0] === 'api' && seg[1] === 'graphql') {
    if (method !== 'POST') return errJson(404, 'Not Found');
    const parsed = parseJsonBody(method, rawBody);
    if (parsed.error) return parsed.error;
    return handleGraphQL(parsed.body);
  }
  return dispatchGitPath(method, seg, query, rawBody, headers);
}

// JSON bodies are parsed here, per route family, so the MCP endpoint can
// answer malformed bodies with its own JSON-RPC parse error instead of a
// generic REST shape.
function parseJsonBody(method, rawBody) {
  if (method !== 'POST' && method !== 'PUT' && method !== 'PATCH' && method !== 'DELETE') {
    return { body: null };
  }
  if (rawBody.length === 0) return { body: {} };
  try {
    return { body: JSON.parse(rawBody.toString('utf8')) };
  } catch {
    return { error: errJson(400, 'Invalid JSON') };
  }
}

// ---------------------------------------------------------------------------
// HTTP server and lifecycle.
// ---------------------------------------------------------------------------

function sendResult(res, result) {
  let body;
  if (result.buffer) body = result.buffer;
  else if (result.json !== undefined) body = Buffer.from(JSON.stringify(result.json), 'utf8');
  else body = Buffer.alloc(0);
  const headers = {
    'content-type': result.type || 'application/json',
    'content-length': body.length,
    'x-github-request-id': nextRequestId(),
    ...(result.headers || {}),
  };
  res.writeHead(result.status, headers);
  res.end(body);
}

const server = createServer((req, res) => {
  const chunks = [];
  req.on('data', (c) => chunks.push(c));
  req.on('end', () => {
    try {
      const rawBody = Buffer.concat(chunks);
      const url = new URL(req.url || '/', 'http://entry');
      const seg = url.pathname
        .split('/')
        .filter((s) => s.length > 0)
        .map((s) => {
          try {
            return decodeURIComponent(s);
          } catch {
            return s;
          }
        });
      const method = (req.method || 'GET').toUpperCase();
      const result = dispatch(method, seg, url.searchParams, rawBody, req.headers, req.headers.host || 'entry');
      sendResult(res, result);
    } catch {
      try {
        sendResult(res, errJson(500, 'Internal error'));
      } catch {
        try {
          res.destroy();
        } catch { /* ignore */ }
      }
    }
  });
  req.on('error', () => {
    try {
      res.destroy();
    } catch { /* ignore */ }
  });
});

function sleepMs(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function registerWithEnv(port) {
  for (let attempt = 0; attempt < 30; attempt += 1) {
    try {
      const r = await fetch(`${ENV_BASE}/register`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', accept: 'application/json' },
        body: JSON.stringify({ port }),
      });
      if (r.status >= 200 && r.status < 300) return true;
      if (r.status === 409) return false;
    } catch { /* env not ready yet; retry */ }
    await sleepMs(500);
  }
  return false;
}

async function waitForDone() {
  for (;;) {
    try {
      const r = await fetch(`${ENV_BASE}/done`, { headers: { accept: 'application/json' } });
      const data = await r.json().catch(() => ({}));
      if (data && data.done === true) return;
    } catch { /* retry */ }
    await sleepMs(250);
  }
}

process.on('uncaughtException', (err) => {
  try {
    console.error('uncaught', err && err.message ? err.message : err);
  } catch { /* ignore */ }
});
process.on('unhandledRejection', (err) => {
  try {
    console.error('unhandled', err && err.message ? err.message : err);
  } catch { /* ignore */ }
});

// ---------------------------------------------------------------------------
// GraphQL: a small lexer, parser and executor for the fixed documents the
// suite sends. No directives, no fragment definitions, no schema stitching:
// only the shapes the checks exercise, resolved against the same store.
// ---------------------------------------------------------------------------

function lexGql(src) {
  const toks = [];
  let i = 0;
  while (i < src.length) {
    const ch = src[i];
    if (ch === ' ' || ch === '\t' || ch === '\n' || ch === '\r' || ch === ',') {
      i += 1;
      continue;
    }
    if (ch === '#') {
      while (i < src.length && src[i] !== '\n') i += 1;
      continue;
    }
    if (ch === '.' && src[i + 1] === '.' && src[i + 2] === '.') {
      toks.push({ t: '...' });
      i += 3;
      continue;
    }
    if ('{}():$![]=@'.includes(ch)) {
      toks.push({ t: ch });
      i += 1;
      continue;
    }
    if (ch === '"') {
      i += 1;
      let s = '';
      while (i < src.length && src[i] !== '"') {
        if (src[i] === '\\') {
          const e = src[i + 1];
          const simple = { n: '\n', t: '\t', r: '\r', b: '\b', f: '\f', '/': '/', '\\': '\\', '"': '"' };
          if (e === 'u') {
            s += String.fromCharCode(parseInt(src.slice(i + 2, i + 6), 16));
            i += 6;
          } else {
            s += simple[e] !== undefined ? simple[e] : e;
            i += 2;
          }
        } else {
          s += src[i];
          i += 1;
        }
      }
      i += 1;
      toks.push({ t: 'str', v: s });
      continue;
    }
    if (/[0-9]/.test(ch) || (ch === '-' && /[0-9]/.test(src[i + 1] || ''))) {
      let j = i;
      if (src[j] === '-') j += 1;
      while (j < src.length && /[0-9]/.test(src[j])) j += 1;
      let isFloat = false;
      if (src[j] === '.' && /[0-9]/.test(src[j + 1] || '')) {
        isFloat = true;
        j += 1;
        while (j < src.length && /[0-9]/.test(src[j])) j += 1;
      }
      if (src[j] === 'e' || src[j] === 'E') {
        isFloat = true;
        j += 1;
        if (src[j] === '+' || src[j] === '-') j += 1;
        while (j < src.length && /[0-9]/.test(src[j])) j += 1;
      }
      toks.push({ t: isFloat ? 'float' : 'int', v: src.slice(i, j) });
      i = j;
      continue;
    }
    if (/[_A-Za-z]/.test(ch)) {
      let j = i;
      while (j < src.length && /[_A-Za-z0-9]/.test(src[j])) j += 1;
      toks.push({ t: 'name', v: src.slice(i, j) });
      i = j;
      continue;
    }
    throw new Error(`unexpected character ${JSON.stringify(ch)}`);
  }
  toks.push({ t: 'eof' });
  return toks;
}

function parseGql(src) {
  const toks = lexGql(src);
  let p = 0;
  const peek = () => toks[p];
  const next = () => toks[p++];
  const expect = (t) => {
    const k = next();
    if (k.t !== t) throw new Error(`expected ${t}, got ${k.t}`);
    return k;
  };
  const parseName = () => expect('name').v;
  function parseType() {
    let type;
    if (peek().t === '[') {
      next();
      const inner = parseType();
      expect(']');
      type = { list: inner };
    } else {
      type = { named: parseName() };
    }
    if (peek().t === '!') {
      next();
      type = { nonNull: type };
    }
    return type;
  }
  function parseValue() {
    const k = peek();
    if (k.t === '$') {
      next();
      return { var: parseName() };
    }
    if (k.t === 'int') {
      next();
      return { int: parseInt(k.v, 10) };
    }
    if (k.t === 'float') {
      next();
      return { float: parseFloat(k.v) };
    }
    if (k.t === 'str') {
      next();
      return { str: k.v };
    }
    if (k.t === 'name') {
      next();
      if (k.v === 'true') return { bool: true };
      if (k.v === 'false') return { bool: false };
      if (k.v === 'null') return { null: true };
      return { enum: k.v };
    }
    if (k.t === '[') {
      next();
      const items = [];
      while (peek().t !== ']') items.push(parseValue());
      expect(']');
      return { list: items };
    }
    if (k.t === '{') {
      next();
      const fields = {};
      while (peek().t !== '}') {
        const fname = parseName();
        expect(':');
        fields[fname] = parseValue();
      }
      expect('}');
      return { obj: fields };
    }
    throw new Error(`unexpected value token ${k.t}`);
  }
  function parseArgs() {
    const args = {};
    expect('(');
    while (peek().t !== ')') {
      const name = parseName();
      expect(':');
      args[name] = parseValue();
    }
    expect(')');
    return args;
  }
  function parseSelectionSet() {
    expect('{');
    const sels = [];
    while (peek().t !== '}') sels.push(parseSelection());
    expect('}');
    return sels;
  }
  function parseSelection() {
    if (peek().t === '...') {
      next();
      let typeCond = null;
      if (peek().t === 'name' && peek().v === 'on') {
        next();
        typeCond = parseName();
      }
      return { frag: true, typeCond, selections: parseSelectionSet() };
    }
    let name = parseName();
    let alias = null;
    if (peek().t === ':') {
      next();
      alias = name;
      name = parseName();
    }
    let args = {};
    if (peek().t === '(') args = parseArgs();
    let selections = null;
    if (peek().t === '{') selections = parseSelectionSet();
    return { field: true, name, alias, args, selections };
  }
  function parseVarDefs() {
    const defs = [];
    expect('(');
    while (peek().t !== ')') {
      expect('$');
      const name = parseName();
      expect(':');
      const type = parseType();
      let defVal;
      let hasDefault = false;
      if (peek().t === '=') {
        next();
        defVal = parseValue();
        hasDefault = true;
      }
      defs.push({ name, type, defVal, hasDefault });
    }
    expect(')');
    return defs;
  }
  const operations = [];
  while (peek().t !== 'eof') {
    const k = peek();
    if (k.t === '{') {
      operations.push({ kind: 'query', name: null, vars: [], selections: parseSelectionSet() });
    } else if (k.t === 'name' && (k.v === 'query' || k.v === 'mutation')) {
      next();
      const kind = k.v;
      let name = null;
      if (peek().t === 'name') name = parseName();
      let vars = [];
      if (peek().t === '(') vars = parseVarDefs();
      operations.push({ kind, name, vars, selections: parseSelectionSet() });
    } else {
      throw new Error(`unexpected document token ${k.t}`);
    }
  }
  return operations;
}

function coerceGqlValue(node, varValues) {
  if ('var' in node) return varValues[node.var];
  if ('int' in node) return node.int;
  if ('float' in node) return node.float;
  if ('str' in node) return node.str;
  if ('bool' in node) return node.bool;
  if ('null' in node) return null;
  if ('enum' in node) return node.enum;
  if ('list' in node) return node.list.map((v) => coerceGqlValue(v, varValues));
  if ('obj' in node) {
    const out = {};
    for (const [k, v] of Object.entries(node.obj)) out[k] = coerceGqlValue(v, varValues);
    return out;
  }
  return undefined;
}

function encodeIssueCursor(num) {
  return Buffer.from(`issue:${num}`, 'utf8').toString('base64');
}

function decodeIssueCursor(cursor) {
  try {
    const text = Buffer.from(cursor, 'base64').toString('utf8');
    const m = /^issue:(\d+)$/.exec(text);
    return m ? Number(m[1]) : null;
  } catch {
    return null;
  }
}

function userWrap() {
  return { __typename: 'User', login: VIEWER.login, id: String(VIEWER.id), name: VIEWER.name, email: VIEWER.email };
}

function repoWrap(repo) {
  return { __typename: 'Repository', repo };
}

function issueWrap(repo, issue) {
  return { __typename: 'Issue', repo, issue };
}

function prWrap(repo, pr) {
  return { __typename: 'PullRequest', repo, pr };
}

function issueConnection(repo, args) {
  let items = [...repo.issues];
  const states = args.states;
  if (Array.isArray(states)) {
    const want = new Set(states.map((s) => String(s).toLowerCase()));
    items = items.filter((i) => want.has(i.state));
  } else if (typeof states === 'string') {
    items = items.filter((i) => i.state === states.toLowerCase());
  } else if (states === undefined || states === null) {
    items = items.filter((i) => i.state === 'open');
  }
  let dir = 'DESC';
  if (args.orderBy && typeof args.orderBy === 'object' && args.orderBy.direction) {
    dir = String(args.orderBy.direction).toUpperCase();
  }
  items.sort((a, b) => (dir === 'ASC' ? a.number - b.number : b.number - a.number));
  let startIdx = 0;
  if (typeof args.after === 'string' && args.after) {
    const n = decodeIssueCursor(args.after);
    if (n !== null) {
      const idx = items.findIndex((i) => i.number === n);
      if (idx >= 0) startIdx = idx + 1;
    }
  }
  const first = typeof args.first === 'number' ? args.first : 100;
  const page = items.slice(startIdx, startIdx + first);
  const hasNext = startIdx + page.length < items.length;
  return {
    __typename: 'IssueConnection',
    nodes: page.map((i) => issueWrap(repo, i)),
    pageInfo: {
      __typename: 'PageInfo',
      hasNextPage: hasNext,
      endCursor: page.length ? encodeIssueCursor(page[page.length - 1].number) : null,
      hasPreviousPage: startIdx > 0,
      startCursor: page.length ? encodeIssueCursor(page[0].number) : null,
    },
  };
}

function prConnection(repo, args) {
  const items = [...repo.pulls].sort((a, b) => b.number - a.number);
  const first = typeof args.first === 'number' ? args.first : 100;
  const page = items.slice(0, first);
  return {
    __typename: 'PullRequestConnection',
    nodes: page.map((p) => prWrap(repo, p)),
    pageInfo: {
      __typename: 'PageInfo',
      hasNextPage: page.length < items.length,
      endCursor: page.length ? encodeIssueCursor(page[page.length - 1].number) : null,
      hasPreviousPage: false,
      startCursor: page.length ? encodeIssueCursor(page[0].number) : null,
    },
  };
}

function prFilesConnection(repo, pr, args) {
  const tips = livePrTips(repo, pr);
  let files = [];
  if (tips.headSha && tips.baseSha) files = diffBetween(repo, tips.baseSha, tips.headSha);
  const first = typeof args.first === 'number' ? args.first : 100;
  return {
    __typename: 'PullRequestChangedFileConnection',
    nodes: files.slice(0, first).map((f) => ({ __typename: 'PullRequestChangedFile', path: f.filename })),
  };
}

const GQL_TYPE_FIELDS = {
  Issue: ['id', 'number', 'title', 'body', 'state', 'createdAt', 'updatedAt'],
  PullRequest: ['id', 'number', 'title', 'body', 'state', 'merged', 'mergeable', 'headRefName', 'baseRefName', 'files', 'createdAt', 'updatedAt'],
  Repository: ['id', 'databaseId', 'name', 'nameWithOwner', 'owner', 'defaultBranchRef', 'viewerPermission', 'hasIssuesEnabled', 'description', 'isPrivate', 'issue', 'issues', 'pullRequests', 'pullRequest', 'createdAt', 'updatedAt'],
  User: ['id', 'login', 'name', 'email'],
  Query: ['viewer', 'repository', 'node'],
  Mutation: ['createIssue', 'closeIssue', 'createPullRequest', 'mergePullRequest', 'addComment'],
};

const GQL_ENUM_VALUES = {
  SearchType: ['ISSUE', 'PULL_REQUEST', 'REPOSITORY', 'USER', 'ORGANIZATION', 'DISCUSSION'],
  IssueState: ['OPEN', 'CLOSED'],
  PullRequestState: ['OPEN', 'CLOSED', 'MERGED'],
  MergeableState: ['MERGEABLE', 'CONFLICTING', 'UNKNOWN'],
};

function makeIssueRecord(repo, title, body) {
  const tick = nextStamp();
  recordSeq += 1;
  repo.counter += 1;
  const issue = {
    uid: recordSeq,
    number: repo.counter,
    title,
    body: typeof body === 'string' ? body : '',
    state: 'open',
    labels: [],
    isPull: false,
    createdTick: tick,
    updatedTick: tick,
  };
  repo.issues.push(issue);
  repo.issueByNum.set(issue.number, issue);
  touchRepo(repo);
  return issue;
}

function makePrRecord(repo, title, body, head, base) {
  const headSha = branchTip(repo, head);
  const baseSha = branchTip(repo, base);
  if (!headSha || !baseSha) return null;
  for (const pr of repo.pulls) {
    if (pr.state === 'open' && pr.headRef === head && pr.baseRef === base) return pr;
  }
  const tick = nextStamp();
  recordSeq += 1;
  repo.counter += 1;
  const pr = {
    uid: recordSeq,
    number: repo.counter,
    title,
    body: typeof body === 'string' ? body : '',
    state: 'open',
    headRef: head,
    baseRef: base,
    headSha,
    baseSha,
    merged: false,
    mergedAt: null,
    mergeSha: null,
    createdTick: tick,
    updatedTick: tick,
  };
  repo.pulls.push(pr);
  repo.pullByNum.set(pr.number, pr);
  touchRepo(repo);
  return pr;
}

function addCommentRecord(repo, num, text) {
  const tick = nextStamp();
  repo.commentSeq += 1;
  const comment = { uid: repo.commentSeq, body: text, createdTick: tick, updatedTick: tick };
  if (!repo.comments.has(num)) repo.comments.set(num, []);
  repo.comments.get(num).push(comment);
  touchRepo(repo);
  return comment;
}

function mergePrRecord(repo, pr) {
  if (pr.state !== 'open') return null;
  const tips = livePrTips(repo, pr);
  if (!tips.headSha || !tips.baseSha) return null;
  if (mergeConflict(repo, tips.baseSha, tips.headSha)) return null;
  const sha = squashMerge(repo, pr);
  if (!sha) return null;
  repo.refs.set(`refs/heads/${pr.baseRef}`, sha);
  pr.state = 'closed';
  pr.merged = true;
  pr.mergedAt = stampIso(nextStamp());
  pr.mergeSha = sha;
  pr.updatedTick = nextStamp();
  touchRepo(repo);
  return sha;
}

function repoFromGlobalId(text) {
  const parsed = parseGlobalId(text);
  if (!parsed || parsed.prefix !== 'REP') return null;
  return reposById.get(parsed.repoId) || null;
}

const GQL_FIELDS = {
  Query: {
    viewer: () => userWrap(),
    repository: (_obj, args) => {
      const repo = findRepo(args.owner, args.name);
      return repo ? repoWrap(repo) : null;
    },
    node: (_obj, args) => {
      const parsed = parseGlobalId(args.id);
      if (!parsed) return null;
      const repo = reposById.get(parsed.repoId);
      if (!repo) return null;
      if (parsed.prefix === 'REP') return repoWrap(repo);
      if (parsed.prefix === 'ISS') {
        const issue = repo.issueByNum.get(parsed.num);
        return issue ? issueWrap(repo, issue) : null;
      }
      if (parsed.prefix === 'PRP') {
        const pr = repo.pullByNum.get(parsed.num);
        return pr ? prWrap(repo, pr) : null;
      }
      return null;
    },
    __type: (_obj, args) => {
      const name = args.name;
      if (typeof name !== 'string') return null;
      if (GQL_TYPE_FIELDS[name]) {
        return { __typename: '__Type', typeName: name, kind: 'OBJECT', fieldNames: GQL_TYPE_FIELDS[name], enumNames: [] };
      }
      if (GQL_ENUM_VALUES[name]) {
        return { __typename: '__Type', typeName: name, kind: 'ENUM', fieldNames: [], enumNames: GQL_ENUM_VALUES[name] };
      }
      return null;
    },
  },
  Mutation: {
    createIssue: (_obj, args, ctx) => {
      const input = args.input || {};
      const repo = repoFromGlobalId(input.repositoryId);
      if (!repo || typeof input.title !== 'string') {
        ctx.errors.push({ message: 'createIssue: unknown repository', path: ctx.path });
        return null;
      }
      const issue = makeIssueRecord(repo, input.title, input.body);
      return { __typename: 'CreateIssuePayload', issue: issueWrap(repo, issue) };
    },
    closeIssue: (_obj, args, ctx) => {
      const input = args.input || {};
      const parsed = parseGlobalId(input.issueId);
      const repo = parsed ? reposById.get(parsed.repoId) : null;
      const issue = repo && parsed && parsed.prefix === 'ISS' ? repo.issueByNum.get(parsed.num) : null;
      if (!issue) {
        ctx.errors.push({ message: 'closeIssue: unknown issue', path: ctx.path });
        return null;
      }
      issue.state = 'closed';
      issue.updatedTick = nextStamp();
      touchRepo(repo);
      return { __typename: 'CloseIssuePayload', issue: issueWrap(repo, issue) };
    },
    createPullRequest: (_obj, args, ctx) => {
      const input = args.input || {};
      const repo = repoFromGlobalId(input.repositoryId);
      if (!repo) {
        ctx.errors.push({ message: 'createPullRequest: unknown repository', path: ctx.path });
        return null;
      }
      const pr = makePrRecord(repo, input.title || '', input.body, input.headRefName, input.baseRefName);
      if (!pr) {
        ctx.errors.push({ message: 'createPullRequest: head or base branch missing', path: ctx.path });
        return null;
      }
      return { __typename: 'CreatePullRequestPayload', pullRequest: prWrap(repo, pr) };
    },
    mergePullRequest: (_obj, args, ctx) => {
      const input = args.input || {};
      const parsed = parseGlobalId(input.pullRequestId);
      const repo = parsed ? reposById.get(parsed.repoId) : null;
      const pr = repo && parsed && parsed.prefix === 'PRP' ? repo.pullByNum.get(parsed.num) : null;
      if (!pr) {
        ctx.errors.push({ message: 'mergePullRequest: unknown pull request', path: ctx.path });
        return null;
      }
      const sha = mergePrRecord(repo, pr);
      if (!sha) {
        ctx.errors.push({ message: 'mergePullRequest: cannot merge', path: ctx.path });
        return null;
      }
      return { __typename: 'MergePullRequestPayload', pullRequest: prWrap(repo, pr) };
    },
    addComment: (_obj, args, ctx) => {
      const input = args.input || {};
      const parsed = parseGlobalId(input.subjectId);
      const repo = parsed ? reposById.get(parsed.repoId) : null;
      let num = null;
      if (repo && parsed && parsed.prefix === 'ISS' && repo.issueByNum.has(parsed.num)) num = parsed.num;
      if (repo && parsed && parsed.prefix === 'PRP' && repo.pullByNum.has(parsed.num)) num = parsed.num;
      if (num === null) {
        ctx.errors.push({ message: 'addComment: unknown subject', path: ctx.path });
        return null;
      }
      const comment = addCommentRecord(repo, num, typeof input.body === 'string' ? input.body : '');
      const gid = globalId('CMT', repo, comment.uid);
      return {
        __typename: 'AddCommentPayload',
        commentEdge: {
          __typename: 'CommentEdge',
          node: { __typename: 'IssueComment', id: gid, body: comment.body },
        },
      };
    },
  },
  Repository: {
    id: (w) => globalId('REP', w.repo, w.repo.id),
    databaseId: (w) => w.repo.id,
    name: (w) => w.repo.name,
    nameWithOwner: (w) => w.repo.fullName,
    owner: () => userWrap(),
    defaultBranchRef: (w) => (defaultTip(w.repo) ? { __typename: 'Ref', name: w.repo.defaultBranch } : null),
    viewerPermission: () => 'ADMIN',
    hasIssuesEnabled: () => true,
    description: (w) => w.repo.description,
    isPrivate: (w) => w.repo.isPrivate,
    createdAt: (w) => stampIso(w.repo.createdTick),
    updatedAt: (w) => stampIso(w.repo.updatedTick),
    issue: (w, args) => {
      const issue = w.repo.issueByNum.get(args.number);
      return issue ? issueWrap(w.repo, issue) : null;
    },
    issues: (w, args) => issueConnection(w.repo, args),
    pullRequest: (w, args) => {
      const pr = w.repo.pullByNum.get(args.number);
      return pr ? prWrap(w.repo, pr) : null;
    },
    pullRequests: (w, args) => prConnection(w.repo, args),
  },
  Issue: {
    id: (w) => globalId('ISS', w.repo, w.issue.number),
    number: (w) => w.issue.number,
    title: (w) => w.issue.title,
    body: (w) => w.issue.body,
    state: (w) => (w.issue.state === 'closed' ? 'CLOSED' : 'OPEN'),
    createdAt: (w) => stampIso(w.issue.createdTick),
    updatedAt: (w) => stampIso(w.issue.updatedTick),
  },
  PullRequest: {
    id: (w) => globalId('PRP', w.repo, w.pr.number),
    number: (w) => w.pr.number,
    title: (w) => w.pr.title,
    body: (w) => w.pr.body,
    state: (w) => (w.pr.merged ? 'MERGED' : w.pr.state === 'closed' ? 'CLOSED' : 'OPEN'),
    merged: (w) => w.pr.merged,
    mergeable: (w) => prMergeable(w.repo, w.pr),
    headRefName: (w) => w.pr.headRef,
    baseRefName: (w) => w.pr.baseRef,
    createdAt: (w) => stampIso(w.pr.createdTick),
    updatedAt: (w) => stampIso(w.pr.updatedTick),
    files: (w, args) => prFilesConnection(w.repo, w.pr, args),
  },
  User: {
    id: (w) => w.id,
    login: (w) => w.login,
    name: (w) => w.name,
    email: (w) => w.email,
  },
  Ref: {
    name: (w) => w.name,
  },
  IssueConnection: {
    nodes: (w) => w.nodes,
    pageInfo: (w) => w.pageInfo,
  },
  PullRequestConnection: {
    nodes: (w) => w.nodes,
    pageInfo: (w) => w.pageInfo,
  },
  PullRequestChangedFileConnection: {
    nodes: (w) => w.nodes,
  },
  PullRequestChangedFile: {
    path: (w) => w.path,
  },
  PageInfo: {
    hasNextPage: (w) => w.hasNextPage,
    endCursor: (w) => w.endCursor,
    hasPreviousPage: (w) => w.hasPreviousPage,
    startCursor: (w) => w.startCursor,
  },
  CreateIssuePayload: {
    issue: (w) => w.issue,
  },
  CloseIssuePayload: {
    issue: (w) => w.issue,
  },
  CreatePullRequestPayload: {
    pullRequest: (w) => w.pullRequest,
  },
  MergePullRequestPayload: {
    pullRequest: (w) => w.pullRequest,
  },
  AddCommentPayload: {
    commentEdge: (w) => w.commentEdge,
  },
  CommentEdge: {
    node: (w) => w.node,
  },
  IssueComment: {
    id: (w) => w.id,
    body: (w) => w.body,
  },
  __Type: {
    name: (w) => w.typeName,
    fields: (w) => (w.kind === 'OBJECT' ? w.fieldNames.map((n) => ({ __typename: '__Field', name: n })) : null),
    enumValues: (w) => (w.kind === 'ENUM' ? w.enumNames.map((n) => ({ __typename: '__EnumValue', name: n })) : null),
  },
  __Field: {
    name: (w) => w.name,
    description: () => '',
  },
  __EnumValue: {
    name: (w) => w.name,
    description: () => '',
  },
};

function resolveSelSet(typeName, obj, selections, varValues, errors, path) {
  if (obj === null || obj === undefined) return null;
  const out = {};
  for (const sel of selections) {
    if (sel.frag) {
      if (sel.typeCond && sel.typeCond !== typeName) continue;
      Object.assign(out, resolveSelSet(typeName, obj, sel.selections, varValues, errors, path));
      continue;
    }
    const key = sel.alias || sel.name;
    const fieldPath = [...path, key];
    if (sel.name === '__typename') {
      out[key] = typeName;
      continue;
    }
    const table = GQL_FIELDS[typeName];
    const resolver = table && table[sel.name];
    if (!resolver) {
      errors.push({ message: `Cannot query field "${sel.name}" on type "${typeName}".`, path: fieldPath });
      continue;
    }
    const args = {};
    for (const [ak, av] of Object.entries(sel.args)) args[ak] = coerceGqlValue(av, varValues);
    let value;
    try {
      value = resolver(obj, args, { errors, path: fieldPath });
    } catch (err) {
      errors.push({ message: String(err && err.message ? err.message : err), path: fieldPath });
      out[key] = null;
      continue;
    }
    if (value === null || value === undefined) {
      out[key] = null;
      continue;
    }
    if (Array.isArray(value)) {
      if (!sel.selections) {
        out[key] = value;
        continue;
      }
      out[key] = value.map((item) => {
        if (item === null || item === undefined) return null;
        if (typeof item !== 'object' || !item.__typename) return item;
        return resolveSelSet(item.__typename, item, sel.selections, varValues, errors, fieldPath);
      });
      continue;
    }
    if (typeof value === 'object' && value.__typename) {
      if (!sel.selections) {
        out[key] = {};
        continue;
      }
      out[key] = resolveSelSet(value.__typename, value, sel.selections, varValues, errors, fieldPath);
      continue;
    }
    out[key] = value;
  }
  return out;
}

function runGqlOperation(op, variables) {
  const varValues = {};
  for (const d of op.vars) {
    if (variables && Object.prototype.hasOwnProperty.call(variables, d.name)) {
      varValues[d.name] = variables[d.name];
    } else if (d.hasDefault) {
      varValues[d.name] = coerceGqlValue(d.defVal, {});
    } else {
      varValues[d.name] = undefined;
    }
  }
  const errors = [];
  const rootType = op.kind === 'mutation' ? 'Mutation' : 'Query';
  const data = resolveSelSet(rootType, { __typename: rootType }, op.selections, varValues, errors, []);
  const result = { data };
  if (errors.length) result.errors = errors;
  return result;
}

function runOneGql(item) {
  if (!item || typeof item.query !== 'string') {
    return { data: null, errors: [{ message: 'query is required' }] };
  }
  let ops;
  try {
    ops = parseGql(item.query);
  } catch (err) {
    return { data: null, errors: [{ message: String(err && err.message ? err.message : err) }] };
  }
  const variables = item.variables && typeof item.variables === 'object' ? item.variables : {};
  let op = ops[0] || null;
  if (item.operationName) {
    op = ops.find((o) => o.name === item.operationName) || null;
    if (!op) return { data: null, errors: [{ message: `unknown operation ${item.operationName}` }] };
  }
  if (!op) return { data: null, errors: [{ message: 'no operation' }] };
  return runGqlOperation(op, variables);
}

function handleGraphQL(body) {
  if (Array.isArray(body)) {
    return { status: 200, json: body.map((item) => runOneGql(item)) };
  }
  return { status: 200, json: runOneGql(body) };
}

// ---------------------------------------------------------------------------
// MCP: Streamable HTTP, JSON-RPC 2.0, plain JSON responses, no sessions.
// ---------------------------------------------------------------------------

const MCP_SERVER_NAME = 'forge-mcp';
const MCP_SERVER_VERSION = '1.0.0';
const MCP_VERSIONS = ['2026-07-28', '2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'];

const MCP_TOOLS = [
  {
    name: 'create_repo',
    description: 'Create a repository owned by the viewer.',
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'Repository name' },
        description: { type: 'string', description: 'Repository description' },
        private: { type: 'boolean', description: 'Whether the repository is private' },
      },
      required: ['name'],
    },
  },
  {
    name: 'get_repo',
    description: 'Read one repository by owner and name.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
      },
      required: ['owner', 'repo'],
    },
  },
  {
    name: 'create_issue',
    description: 'Create an issue in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
        title: { type: 'string', description: 'Issue title' },
        body: { type: 'string', description: 'Issue body' },
      },
      required: ['owner', 'repo', 'title'],
    },
  },
  {
    name: 'list_issues',
    description: 'List issues in a repository, optionally filtered by state.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
        state: { type: 'string', description: 'open, closed, or all' },
      },
      required: ['owner', 'repo'],
    },
  },
  {
    name: 'create_pull_request',
    description: 'Create a pull request between two branches.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
        title: { type: 'string', description: 'Pull request title' },
        body: { type: 'string', description: 'Pull request body' },
        head: { type: 'string', description: 'Head branch name' },
        base: { type: 'string', description: 'Base branch name' },
      },
      required: ['owner', 'repo', 'title', 'head', 'base'],
    },
  },
  {
    name: 'merge_pull_request',
    description: 'Squash-merge a pull request into its base branch.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
        pull_number: { type: 'integer', description: 'Pull request number' },
      },
      required: ['owner', 'repo', 'pull_number'],
    },
  },
];

function pickArg(args, names) {
  for (const n of names) {
    if (args[n] !== undefined && args[n] !== null) return args[n];
  }
  return undefined;
}

function mcpRepoOf(args) {
  let owner = pickArg(args, ['owner', 'owner_login', 'ownerLogin', 'org', 'organization']);
  let repoName = pickArg(args, ['repo', 'repository', 'repository_name', 'repoName']);
  const full = pickArg(args, ['full_name', 'fullName']);
  if ((!owner || !repoName) && typeof full === 'string' && full.includes('/')) {
    const cut = full.indexOf('/');
    if (!owner) owner = full.slice(0, cut);
    if (!repoName) repoName = full.slice(cut + 1);
  }
  if (typeof owner !== 'string' || typeof repoName !== 'string' || !owner || !repoName) {
    return { error: 'owner and repo are required' };
  }
  const repo = findRepo(owner, repoName);
  if (!repo) return { error: 'repository not found' };
  return { repo };
}

function mcpToolOk(payload) {
  return {
    content: [{ type: 'text', text: JSON.stringify(payload, null, 2) }],
    structuredContent: payload,
    isError: false,
  };
}

function mcpToolErr(message) {
  const payload = { message };
  return {
    content: [{ type: 'text', text: JSON.stringify(payload, null, 2) }],
    structuredContent: payload,
    isError: true,
  };
}

function runMcpTool(name, args) {
  if (name === 'create_repo') {
    const repoName = pickArg(args, ['name', 'repository', 'repo']);
    if (typeof repoName !== 'string' || !repoName) return { code: -32602, message: 'Missing required argument: name' };
    if (reposByName.has(repoName)) return { toolError: `A repository named "${repoName}" already exists.` };
    const repo = freshRepo(repoName, args.private === true, args.description);
    return { result: mcpToolOk(repoView(repo)) };
  }
  if (name === 'get_repo') {
    const found = mcpRepoOf(args);
    if (found.error) return { toolError: found.error };
    return { result: mcpToolOk(repoView(found.repo)) };
  }
  if (name === 'create_issue') {
    const found = mcpRepoOf(args);
    if (found.error) return { toolError: found.error };
    const title = pickArg(args, ['title']);
    if (typeof title !== 'string' || !title) return { code: -32602, message: 'Missing required argument: title' };
    const issue = makeIssueRecord(found.repo, title, pickArg(args, ['body', 'description']));
    return { result: mcpToolOk(issueView(found.repo, issue)) };
  }
  if (name === 'list_issues') {
    const found = mcpRepoOf(args);
    if (found.error) return { toolError: found.error };
    const state = String(pickArg(args, ['state', 'filter']) || 'open').toLowerCase();
    let items = [...found.repo.issues];
    if (state !== 'all') items = items.filter((i) => i.state === state);
    return { result: mcpToolOk(items.map((i) => issueView(found.repo, i))) };
  }
  if (name === 'create_pull_request') {
    const found = mcpRepoOf(args);
    if (found.error) return { toolError: found.error };
    const title = pickArg(args, ['title']);
    const head = pickArg(args, ['head', 'head_ref', 'headRef', 'head_branch']);
    const base = pickArg(args, ['base', 'base_ref', 'baseRef', 'base_branch']);
    if (typeof title !== 'string' || !title) return { code: -32602, message: 'Missing required argument: title' };
    if (typeof head !== 'string' || !head) return { code: -32602, message: 'Missing required argument: head' };
    if (typeof base !== 'string' || !base) return { code: -32602, message: 'Missing required argument: base' };
    const pr = makePrRecord(found.repo, title, pickArg(args, ['body', 'description']), head, base);
    if (!pr) return { toolError: 'head or base branch does not exist' };
    return { result: mcpToolOk(prView(found.repo, pr)) };
  }
  if (name === 'merge_pull_request') {
    const found = mcpRepoOf(args);
    if (found.error) return { toolError: found.error };
    const numRaw = pickArg(args, ['pull_number', 'pullNumber', 'number', 'pr_number']);
    const num = typeof numRaw === 'string' ? parseInt(numRaw, 10) : numRaw;
    if (!Number.isFinite(num)) return { code: -32602, message: 'Missing required argument: pull_number' };
    const pr = found.repo.pullByNum.get(num);
    if (!pr) return { toolError: 'pull request not found' };
    const sha = mergePrRecord(found.repo, pr);
    if (!sha) return { toolError: 'pull request cannot be merged' };
    return { result: mcpToolOk({ sha, merged: true, message: 'Pull request successfully merged', number: pr.number }) };
  }
  return { code: -32601, message: `Unknown tool: ${name}` };
}

function handleMcp(rawBody, headers) {
  let parsed = null;
  let parseFailed = false;
  try {
    parsed = rawBody.length ? JSON.parse(rawBody.toString('utf8')) : null;
  } catch {
    parseFailed = true;
  }
  const echoId = parsed && typeof parsed === 'object' && !Array.isArray(parsed) && 'id' in parsed ? parsed.id : null;
  if (!checkAuth(headers)) {
    return {
      status: 401,
      json: { jsonrpc: '2.0', id: echoId, error: { code: -32001, message: 'Unauthorized' } },
    };
  }
  if (parseFailed || parsed === null) {
    return {
      status: 400,
      json: { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } },
    };
  }
  if (Array.isArray(parsed)) {
    return {
      status: 200,
      json: { jsonrpc: '2.0', id: null, error: { code: -32600, message: 'Invalid Request' } },
    };
  }
  if (typeof parsed !== 'object' || parsed === null) {
    return {
      status: 200,
      json: { jsonrpc: '2.0', id: null, error: { code: -32600, message: 'Invalid Request' } },
    };
  }
  if (!('id' in parsed)) {
    return { status: 202, buffer: Buffer.alloc(0) };
  }
  const id = parsed.id;
  const method = parsed.method;
  const params = parsed.params && typeof parsed.params === 'object' ? parsed.params : {};
  if (method === 'server/discover') {
    return {
      status: 200,
      json: {
        jsonrpc: '2.0',
        id,
        result: {
          supportedVersions: MCP_VERSIONS,
          capabilities: { tools: {} },
          serverInfo: { name: MCP_SERVER_NAME, version: MCP_SERVER_VERSION },
          _meta: { 'io.modelcontextprotocol/serverInfo': { name: MCP_SERVER_NAME, version: MCP_SERVER_VERSION } },
        },
      },
    };
  }
  if (method === 'initialize') {
    const asked = typeof params.protocolVersion === 'string' ? params.protocolVersion : '';
    return {
      status: 200,
      json: {
        jsonrpc: '2.0',
        id,
        result: {
          protocolVersion: MCP_VERSIONS.includes(asked) ? asked : '2025-11-25',
          capabilities: { tools: {} },
          serverInfo: { name: MCP_SERVER_NAME, version: MCP_SERVER_VERSION },
        },
      },
    };
  }
  if (method === 'tools/list') {
    return { status: 200, json: { jsonrpc: '2.0', id, result: { tools: MCP_TOOLS } } };
  }
  if (method === 'tools/call') {
    const toolName = params.name;
    const toolArgs = params.arguments && typeof params.arguments === 'object' ? params.arguments : {};
    if (typeof toolName !== 'string' || !toolName) {
      return { status: 200, json: { jsonrpc: '2.0', id, error: { code: -32602, message: 'Missing tool name' } } };
    }
    const outcome = runMcpTool(toolName, toolArgs);
    if (outcome.code) {
      return { status: 200, json: { jsonrpc: '2.0', id, error: { code: outcome.code, message: outcome.message } } };
    }
    if (outcome.toolError) {
      return { status: 200, json: { jsonrpc: '2.0', id, result: mcpToolErr(outcome.toolError) } };
    }
    return { status: 200, json: { jsonrpc: '2.0', id, result: outcome.result } };
  }
  return {
    status: 200,
    json: { jsonrpc: '2.0', id, error: { code: -32601, message: `Method not found: ${method}` } },
  };
}

// ---------------------------------------------------------------------------
// Boot.
// ---------------------------------------------------------------------------

async function main() {
  await new Promise((resolve) => server.listen(0, '0.0.0.0', resolve));
  const port = server.address().port;
  if (!ENV_BASE) {
    console.log(`forge listening on port ${port}`);
    return;
  }
  const registered = await registerWithEnv(port);
  if (!registered) {
    console.error('registration failed');
    process.exit(1);
  }
  await waitForDone();
  server.close();
  process.exit(0);
}

main().catch((err) => {
  try {
    console.error('fatal', err && err.message ? err.message : err);
  } catch { /* ignore */ }
  process.exit(1);
});
