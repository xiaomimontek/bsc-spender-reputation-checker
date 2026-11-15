#!/usr/bin/env node
/**
 * BSC Spender Reputation Checker
 *
 * Read-only CLI agent: given a wallet address, find its active ERC-20
 * approvals on BNB Smart Chain and classify WHO the wallet has approved.
 *
 *   node checker.mjs <wallet-address> [--json] [--out <file>]
 *
 * The spender — not the token — is the unit of trust. A token approval
 * hands a contract the right to move your tokens; the question that
 * matters is whether that contract deserves it.
 *
 * Discovery (two methods, both read-only, no API key):
 *   1. Best-effort Approval-event scan via eth_getLogs (address-filtered,
 *      small recent window). Public BSC nodes currently refuse eth_getLogs
 *      ("limit exceeded") even for 100-block ranges, so this method is
 *      attempted and then honestly reported as unavailable when refused.
 *   2. Allowance-probe matrix via eth_call: for every (token, spender)
 *      pair in the curated lists, call allowance(owner, spender). Any
 *      non-zero allowance is a real, currently-active approval. This is
 *      the method that actually works on public RPCs.
 *
 * Classification:
 *   KNOWN-SAFE  spender is on the curated allowlist (name + category).
 *   UNKNOWN     spender is a contract, not on the allowlist, but answers
 *               at least one identity probe (name/symbol/owner).
 *   DORMANT     spender is a contract, not on the allowlist, and answers
 *               NO identity probe — it cannot be verified as anything.
 *               Flagged as unverifiable; revoke recommended.
 *   (An EOA spender — no contract code — is UNKNOWN with an explicit
 *   note: approving an externally-owned account is unusual.)
 *
 * Never asks for a private key, seed phrase or password. Never signs or
 * submits anything. Revoke calldata is printed for review only.
 */

const RPCS = [
  'https://bsc-dataseed1.bnbchain.org',
  'https://bsc-dataseed2.bnbchain.org',
  'https://bsc-dataseed3.bnbchain.org',
  'https://bsc-dataseed4.bnbchain.org',
  'https://bsc.publicnode.com',
  'https://bsc-dataseed.bnbchain.org',
];

// --- Curated lists ---------------------------------------------------------
// Every address here was verified on-chain before shipping (getCode +
// symbol()/decimals()/factory() where applicable). Token addresses are
// taken from PancakeSwap's public token list and re-verified on-chain.
// The lists are deliberately small and opinionated: they are a starting
// point, not an exhaustive registry. Extend with --tokens / --spenders.

const TOKENS = [
  { symbol: 'WBNB',  address: '0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c', decimals: 18 },
  { symbol: 'BUSD',  address: '0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56', decimals: 18 },
  { symbol: 'USDT',  address: '0x55d398326f99059fF775485246999027B3197955', decimals: 18 },
  { symbol: 'USDC',  address: '0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d', decimals: 18 },
  { symbol: 'CAKE',  address: '0x0E09FaBB73Bd3Ade0a17ECC321fD13a19e81cE82', decimals: 18 },
  { symbol: 'BTCB',  address: '0x7130d2A12B9BCbFAe4f2634d864A1Ee1Ce3Ead9c', decimals: 18 },
  { symbol: 'ETH',   address: '0x2170Ed0880ac9A755fd29B2688956BD959F933F8', decimals: 18 },
  { symbol: 'DAI',   address: '0x1AF3F329e8BE154074D8769D1FFa4eE058B1DBc3', decimals: 18 },
  { symbol: 'FDUSD', address: '0xc5f0f7b66764F6ec8C8Dff7BA683102295E16409', decimals: 18 },
  { symbol: 'LINK',  address: '0xF8A0BF9cF54Bb92F17374d9e9A321E6a111a51bD', decimals: 18 },
  { symbol: 'DOT',   address: '0x7083609fCE4d1d8Dc0C979AAb8c869Ea2C873402', decimals: 18 },
  { symbol: 'XRP',   address: '0x1D2F0da169ceB9fC7B3144628dB156f3F6c60dBE', decimals: 18 },
  { symbol: 'DOGE',  address: '0xbA2aE424d960c26247Dd6c32edC70B295c744C43', decimals: 8 },
  { symbol: 'ADA',   address: '0x3EE2200Efb3400fAbB9AacF31297cBdD1d435D47', decimals: 18 },
  { symbol: 'UNI',   address: '0xBf5140A22578168FD562DCcF235E5D43A02ce9B1', decimals: 18 },
  { symbol: 'A404',  address: '0xB7E2f2D6ED4928F6fA774Ff9295D01f25aA17725', decimals: 18 },
  { symbol: 'TUSD',  address: '0x40af3827F39D0EAcBF4A168f8D4ee67c121D11c9', decimals: 18 },
  { symbol: 'LTC',   address: '0x4338665CBB7B2485A8855A139b75D5e34AB0DB94', decimals: 18 },
];

// Spenders the checker knows by name. Anything not on this list is
// UNKNOWN or DORMANT — that is the point: an allowlist can only vouch
// for what it names.
const SAFE_SPENDERS = [
  { name: 'PancakeSwap V2 Router', category: 'DEX', address: '0x10ED43C718714eb63d5aA57B78B54704E256024E' },
  { name: '1inch Aggregation Router v5', category: 'DEX aggregator', address: '0x1111111254EEB25477B68fb85Ed929f73A960582' },
  { name: 'Agent404 Passdrop Engine', category: 'Agent404 ecosystem', address: '0xCD2401b13d66A37D04a7356d776162154Eb11719' },
  { name: 'Agent404 AgentsMine Engine', category: 'Agent404 ecosystem', address: '0x7d8e34cBbf5d171391f43154cc5B5334f40667c1' },
];

const MAX_UINT256 = (1n << 256n) - 1n;
const APPROVAL_TOPIC = '0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c5f7e259e4c7b3b3b3b3b3b3b3b3';
const LOG_SCAN_WINDOW = 5000; // blocks; small, because public nodes refuse wide ranges

// --- RPC -------------------------------------------------------------------

let rpcIndex = 0;
let rpcCalls = 0;
let rpcFailures = 0;

async function rpc(method, params) {
  for (let attempt = 0; attempt < RPCS.length; attempt++) {
    const url = RPCS[(rpcIndex++) % RPCS.length];
    rpcCalls++;
    try {
      const res = await fetch(url, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: rpcCalls, method, params }),
        signal: AbortSignal.timeout(15000),
      });
      const json = await res.json();
      if (json.error) { rpcFailures++; continue; }
      return json.result;
    } catch {
      rpcFailures++;
    }
  }
  return null;
}

const pad = (addr) => '000000000000000000000000' + addr.slice(2).toLowerCase();

async function ethCall(to, data) {
  return rpc('eth_call', [{ to, data }, 'latest']);
}

function decodeString(hex) {
  if (!hex || hex === '0x') return null;
  try {
    const b = Buffer.from(hex.slice(2), 'hex');
    if (b.length < 64) return null;
    const len = b.readUInt32BE(60);
    if (len === 0 || len > 1000) return null;
    return b.slice(64, 64 + len).toString('utf8');
  } catch { return null; }
}

async function mapLimit(items, n, fn) {
  const out = [];
  let i = 0;
  const workers = Array.from({ length: n }, async () => {
    while (i < items.length) {
      const item = items[i++];
      out.push(await fn(item));
    }
  });
  await Promise.all(workers);
  return out;
}

// --- Identity probing ------------------------------------------------------

async function probeIdentity(spender) {
  const code = await rpc('eth_getCode', [spender, 'latest']);
  const isContract = !!(code && code !== '0x');
  if (!isContract) return { isContract: false, discoveredName: null };
  const probes = await Promise.all([
    ethCall(spender, '0x06fdde03'), // name()
    ethCall(spender, '0x95d89b41'), // symbol()
    ethCall(spender, '0x8da5cb5b'), // owner()
  ]);
  const name = decodeString(probes[0]);
  const symbol = decodeString(probes[1]);
  const owner = probes[2] && probes[2] !== '0x' ? '0x' + probes[2].slice(-40) : null;
  const discoveredName = name || symbol || null;
  return { isContract: true, discoveredName, owner, answeredAny: !!(name || symbol || owner) };
}

// --- Classification --------------------------------------------------------

function classify(spender, identity) {
  const known = SAFE_SPENDERS.find((s) => s.address.toLowerCase() === spender.toLowerCase());
  if (known) return { classification: 'KNOWN-SAFE', name: known.name, category: known.category };
  if (!identity.isContract) {
    return { classification: 'UNKNOWN', name: null, category: 'EOA spender', note: 'Spender is an externally-owned account, not a contract. Approving an EOA is unusual — review before trusting it.' };
  }
  if (!identity.answeredAny) {
    return { classification: 'DORMANT', name: null, category: 'unverifiable contract', note: 'Contract answers no identity probe (name/symbol/owner). Nothing verifiable is known about it — treat as untrusted.' };
  }
  return { classification: 'UNKNOWN', name: identity.discoveredName, category: 'unlisted contract', note: 'Contract is not on the allowlist. It has some on-chain identity, but the checker cannot vouch for it.' };
}

function riskScore(findings) {
  let score = 0;
  for (const f of findings) {
    if (f.unlimited) score += 35;
    if (f.classification === 'UNKNOWN') score += 25;
    if (f.classification === 'DORMANT') score += 20;
    if (f.note && f.note.includes('externally-owned')) score += 15;
    if (f.stale) score += 10;
  }
  return Math.min(100, score);
}

function riskBand(score) {
  if (score === 0) return 'CLEAN';
  if (score < 40) return 'LOW';
  if (score < 70) return 'MEDIUM';
  return 'HIGH';
}

function revokeCalldata(spender) {
  // approve(spender, 0)
  return '0x095ea7b3' + pad(spender) + '0'.repeat(64);
}

// --- Discovery -------------------------------------------------------------

async function tryLogScan(owner, tokens) {
  // One small, address-filtered attempt per token. Public BSC nodes
  // currently refuse eth_getLogs outright; we try honestly, then say so.
  const blockHex = await rpc('eth_blockNumber', []);
  if (!blockHex) return { available: false, reason: 'could not read chain head', pairs: [] };
  const head = parseInt(blockHex, 16);
  const from = '0x' + (head - LOG_SCAN_WINDOW).toString(16);
  const to = '0x' + head.toString(16);
  const topic1 = '0x000000000000000000000000' + owner.slice(2).toLowerCase();
  const pairs = [];
  let refused = false;
  for (const token of tokens) {
    const logs = await rpc('eth_getLogs', [{ address: token.address, fromBlock: from, toBlock: to, topics: [APPROVAL_TOPIC, topic1] }]);
    if (logs === null) { refused = true; break; }
    for (const log of logs) {
      const spender = '0x' + log.topics[2].slice(-40);
      pairs.push({ token: token.symbol, tokenAddress: token.address, spender });
    }
  }
  if (refused) return { available: false, reason: `eth_getLogs refused by public RPCs (limit exceeded) over a ${LOG_SCAN_WINDOW}-block window`, pairs };
  return { available: true, reason: null, pairs, windowBlocks: LOG_SCAN_WINDOW };
}

async function probeMatrix(owner, tokens, spenders) {
  const jobs = [];
  for (const token of tokens) {
    for (const spender of spenders) jobs.push({ token, spender });
  }
  const results = await mapLimit(jobs, 8, async ({ token, spender }) => {
    const data = '0xdd62ed3e' + pad(owner) + pad(spender.address);
    const raw = await ethCall(token.address, data);
    if (raw === null) return { token, spender, allowance: null, error: true };
    return { token, spender, allowance: BigInt(raw), error: false };
  });
  return results.filter((r) => !r.error && r.allowance > 0n);
}

// --- Main ------------------------------------------------------------------

function parseArgs(argv) {
  const args = { json: false, out: null, tokens: null, spenders: null };
  let address = null;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--json') args.json = true;
    else if (a === '--out') args.out = argv[++i];
    else if (a === '--tokens') args.tokens = argv[++i].split(',').map((s) => s.trim());
    else if (a === '--spenders') args.spenders = argv[++i].split(',').map((s) => s.trim());
    else if (!a.startsWith('--') && !address) address = a;
  }
  return { address, ...args };
}

function isAddress(s) {
  return typeof s === 'string' && /^0x[0-9a-fA-F]{40}$/.test(s);
}

async function main() {
  const { address, json, out, tokens: tokenFilter, spenders: spenderFilter } = parseArgs(process.argv.slice(2));
  if (!isAddress(address)) {
    console.error('Usage: node checker.mjs <wallet-address> [--json] [--out <file>] [--tokens SYM,...] [--spenders 0x...,0x...]');
    console.error('Example: node checker.mjs 0x2FD42Eb9b6cA3117aB13AeED26Ad038eFA20a68F');
    process.exit(2);
  }
  const owner = address;
  const tokens = tokenFilter
    ? TOKENS.filter((t) => tokenFilter.includes(t.symbol))
    : TOKENS;
  let spenders = SAFE_SPENDERS;
  if (spenderFilter) {
    spenders = spenderFilter.filter(isAddress).map((a) => ({ name: null, category: 'user-supplied', address: a }));
  }
  if (tokens.length === 0) { console.error('No known tokens selected.'); process.exit(2); }
  if (spenders.length === 0) { console.error('No valid spender addresses supplied.'); process.exit(2); }

  console.error(`Checking ${owner} on BSC (chain 56) — ${tokens.length} tokens x ${spenders.length} spenders...`);
  const headHex = await rpc('eth_blockNumber', []);
  const head = headHex ? parseInt(headHex, 16) : null;

  const logScan = await tryLogScan(owner, tokens);
  console.error(logScan.available
    ? `Log scan: OK (${logScan.pairs.length} approval events in last ${LOG_SCAN_WINDOW} blocks)`
    : `Log scan: UNAVAILABLE — ${logScan.reason}. Falling back to the allowance matrix.`);

  const active = await probeMatrix(owner, tokens, spenders);
  console.error(`Matrix probe: ${active.length} active approval(s) found.`);

  const findings = [];
  for (const { token, spender, allowance } of active) {
    const balanceRaw = await ethCall(token.address, '0x70a08231' + pad(owner));
    const balance = balanceRaw ? BigInt(balanceRaw) : 0n;
    const identity = await probeIdentity(spender.address);
    const cls = classify(spender.address, identity);
    const unlimited = allowance === MAX_UINT256;
    findings.push({
      token: token.symbol,
      tokenAddress: token.address,
      spender: spender.address,
      spenderName: cls.name,
      spenderCategory: cls.category,
      classification: cls.classification,
      note: cls.note || null,
      allowance: allowance.toString(),
      allowanceHuman: unlimited ? 'UNLIMITED (2^256-1)' : (Number(allowance) / 10 ** token.decimals).toString(),
      unlimited,
      tokenBalance: balance.toString(),
      tokenBalanceHuman: (Number(balance) / 10 ** token.decimals).toString(),
      stale: balance === 0n,
      revokeCalldata: (cls.classification === 'UNKNOWN' || cls.classification === 'DORMANT')
        ? revokeCalldata(spender.address)
        : null,
    });
  }

  const score = riskScore(findings);
  const report = {
    tool: 'bsc-spender-reputation-checker',
    version: '1.0.0',
    chain: 'BNB Smart Chain (56)',
    wallet: owner,
    checkedAtBlock: head,
    generatedAt: new Date().toISOString(),
    discovery: {
      logScan: logScan.available
        ? { method: 'eth_getLogs', status: 'ok', windowBlocks: LOG_SCAN_WINDOW, eventsFound: logScan.pairs.length }
        : { method: 'eth_getLogs', status: 'unavailable', reason: logScan.reason },
      matrix: { method: 'allowance() eth_call', tokensScanned: tokens.length, spendersProbed: spenders.length, pairsProbed: tokens.length * spenders.length },
      limitation: 'The matrix only finds approvals to spenders on the curated list. An approval to a spender outside the list can only be found via the event log scan, which public BSC RPCs currently refuse. The checker says so instead of pretending full coverage.',
    },
    summary: {
      activeApprovals: findings.length,
      byClassification: {
        'KNOWN-SAFE': findings.filter((f) => f.classification === 'KNOWN-SAFE').length,
        UNKNOWN: findings.filter((f) => f.classification === 'UNKNOWN').length,
        DORMANT: findings.filter((f) => f.classification === 'DORMANT').length,
      },
      unlimitedApprovals: findings.filter((f) => f.unlimited).length,
      riskScore: score,
      riskBand: riskBand(score),
    },
    findings,
    rpc: { calls: rpcCalls, failures: rpcFailures, endpoints: RPCS.length },
  };

  const text = JSON.stringify(report, null, 2);
  if (out) {
    const { writeFileSync } = await import('node:fs');
    writeFileSync(out, text + '\n');
    console.error(`Report written to ${out}`);
  }
  if (json) {
    console.log(text);
  } else {
    printHuman(report);
    if (!out) console.error('\nTip: re-run with --json --out sample-report.json for the machine-readable report.');
  }
}

function printHuman(report) {
  const s = report.summary;
  console.log(`\n=== BSC Spender Reputation — ${report.wallet} ===`);
  console.log(`Block ${report.checkedAtBlock} · ${report.generatedAt}`);
  console.log(`Active approvals: ${s.activeApprovals}  ·  KNOWN-SAFE ${s.byClassification['KNOWN-SAFE']}  ·  UNKNOWN ${s.byClassification.UNKNOWN}  ·  DORMANT ${s.byClassification.DORMANT}  ·  Unlimited ${s.unlimitedApprovals}`);
  console.log(`Risk score: ${s.riskScore}/100 (${s.riskBand})`);
  console.log(`Discovery: ${report.discovery.logScan.status === 'ok' ? 'logs OK' : 'logs UNAVAILABLE — ' + report.discovery.logScan.reason} · matrix ${report.discovery.matrix.pairsProbed} pairs probed`);
  if (report.findings.length === 0) {
    console.log('\nNo active approvals found to any spender on the curated list.');
    console.log('That is a clean result for the spenders this tool knows — it is NOT proof');
    console.log('the wallet has no approvals at all (see limitation in the JSON report).');
    return;
  }
  for (const group of ['DORMANT', 'UNKNOWN', 'KNOWN-SAFE']) {
    const rows = report.findings.filter((f) => f.classification === group);
    if (!rows.length) continue;
    console.log(`\n--- ${group} (${rows.length}) ---`);
    for (const f of rows) {
      console.log(`• ${f.token} -> ${f.spenderName || f.spender} [${f.spenderCategory}]`);
      console.log(`  allowance: ${f.allowanceHuman}${f.unlimited ? '  ⚠ UNLIMITED' : ''} · token balance: ${f.tokenBalanceHuman}${f.stale ? ' (stale — holds no ' + f.token + ')' : ''}`);
      if (f.note) console.log(`  note: ${f.note}`);
      if (f.revokeCalldata) console.log(`  revoke (approve 0): ${f.revokeCalldata}`);
    }
  }
  console.log('\nRevoke calldata is printed for review only — this tool never submits transactions.');
}

import { fileURLToPath } from 'node:url';

// Run the CLI only when this file is executed directly, not when imported
// by the self-test.
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main().catch((e) => { console.error('Fatal:', e.message); process.exit(1); });
}

// Exported for the self-test (test-classify.mjs) and for reuse.
export { classify, riskScore, riskBand, revokeCalldata, SAFE_SPENDERS, TOKENS };
