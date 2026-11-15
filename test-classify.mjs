#!/usr/bin/env node
/**
 * Self-test for the classification logic in checker.mjs.
 *
 * The inputs here are SYNTHETIC — they exercise the pure classify() /
 * riskScore() / revokeCalldata() functions with fabricated identities so
 * every classification path is demonstrated. They are NOT claims about
 * any real wallet. The real on-chain run is sample-report.json.
 *
 *   node test-classify.mjs
 */

import { classify, riskScore, riskBand, revokeCalldata } from './checker.mjs';

let passed = 0;
let failed = 0;
function check(name, cond) {
  if (cond) { passed++; console.log(`  ok  ${name}`); }
  else { failed++; console.log(`  FAIL ${name}`); }
}

console.log('Classification paths (synthetic inputs):');

// 1. Known-safe: a spender on the allowlist.
const pcs = '0x10ED43C718714eb63d5aA57B78B54704E256024E';
const r1 = classify(pcs, { isContract: true, discoveredName: null, answeredAny: true });
check('allowlisted router -> KNOWN-SAFE', r1.classification === 'KNOWN-SAFE' && r1.name === 'PancakeSwap V2 Router');

// 2. Unknown: a contract with some identity, not on the allowlist.
const someContract = '0x1111111111111111111111111111111111111111';
const r2 = classify(someContract, { isContract: true, discoveredName: 'SomeDex', answeredAny: true });
check('unlisted contract with a name -> UNKNOWN', r2.classification === 'UNKNOWN' && r2.name === 'SomeDex');

// 3. Dormant: a contract that answers no identity probe at all.
const r3 = classify(someContract, { isContract: true, discoveredName: null, answeredAny: false });
check('unverifiable contract -> DORMANT', r3.classification === 'DORMANT');

// 4. EOA spender: no contract code.
const r4 = classify(someContract, { isContract: false, discoveredName: null });
check('EOA spender -> UNKNOWN with EOA note', r4.classification === 'UNKNOWN' && /externally-owned/.test(r4.note || ''));

// 5. Revoke calldata is approve(spender, 0).
const cd = revokeCalldata(pcs);
check('revoke calldata = approve(spender, 0)', cd === '0x095ea7b3' + '00000000000000000000000010ed43c718714eb63d5aa57b78b54704e256024e' + '0'.repeat(64));

// 6. Risk scoring: unlimited + unknown + dormant + stale.
const findings = [
  { unlimited: true, classification: 'UNKNOWN', stale: false, note: '' },
  { unlimited: false, classification: 'DORMANT', stale: true, note: '' },
];
const score = riskScore(findings); // 35 + 25 + 20 + 10 = 90
check('risk score 35+25+20+10 = 90', score === 90);
check('risk band for 90 is HIGH', riskBand(90) === 'HIGH');
check('risk band for 0 is CLEAN', riskBand(0) === 'CLEAN');
check('empty findings score 0', riskScore([]) === 0);

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
