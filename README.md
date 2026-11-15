# BSC Spender Reputation Checker

A read-only CLI agent that answers one question about a BNB Smart Chain
wallet: **who have you approved — and should you trust them?**

An ERC-20 approval hands a contract the right to move your tokens. Most
wallet-security tools list *which tokens* you approved. This one lists
*which spenders* you approved, and classifies each spender by reputation:
known-safe, unknown, or dormant (unverifiable).

Built for [Agent Games by zkVerify](https://agentgames.zkverify.io) —
Wildcard Track, Season 01.

## The problem

Token approvals are the quietest way wallets get drained. A user approves
a contract once — to swap, to stake, to claim — and the approval stays
open forever, often unlimited (`2^256-1`). Months later the contract is
abandoned, upgraded, or was malicious all along, and the approval is
still there, still unlimited. Approval phishing works precisely because
nobody re-checks old approvals, and because the question "which token did
I approve?" is less useful than "who did I approve?".

## What it does

```
node checker.mjs <wallet-address>
```

For a wallet it:

1. **Discovers active approvals.** Two methods, both read-only, no API
   key: a best-effort `eth_getLogs` Approval-event scan, and an
   `allowance()` probe matrix (curated tokens × curated spenders) via
   `eth_call`. Public BSC nodes currently refuse `eth_getLogs`, so the
   matrix is the method that works — the report says this plainly
   instead of pretending full coverage.
2. **Classifies every spender.**
   - `KNOWN-SAFE` — on the curated allowlist, with a name and category.
   - `UNKNOWN` — a contract not on the allowlist, but with some
     verifiable on-chain identity.
   - `DORMANT` — a contract that answers no identity probe at all.
     Nothing verifiable is known about it; revoke recommended.
   - An EOA spender (no contract code) is flagged `UNKNOWN` with an
     explicit note — approving an externally-owned account is unusual.
3. **Scores the risk** (0–100, formula in `DESIGN.md`) and prints
   `approve(spender, 0)` revoke calldata for every `UNKNOWN`/`DORMANT`
   finding — for review only. This tool never submits transactions.

## Example

```
$ node checker.mjs 0x2FD42Eb9b6cA3117aB13AeED26Ad038eFA20a68F

=== BSC Spender Reputation — 0x2FD42E… ===
Block 133634081 · 2026-11-14T23:46:35Z
Active approvals: 0  ·  KNOWN-SAFE 0  ·  UNKNOWN 0  ·  DORMANT 0  ·  Unlimited 0
Risk score: 0/100 (CLEAN)
Discovery: logs UNAVAILABLE — eth_getLogs refused by public RPCs … · matrix 72 pairs probed

No active approvals found to any spender on the curated list.
```

A real run against a real wallet is in [`sample-report.json`](sample-report.json)
(machine-readable, `--json --out sample-report.json`). That wallet is
clean for the spenders this tool knows — which is a genuine result, and
the report is careful about what it does *not* prove.

## How to run

```sh
node checker.mjs <wallet-address> [--json] [--out <file>]
  [--tokens WBNB,BUSD,...] [--spenders 0x...,0x...]
```

- Node 18+ (uses built-in `fetch`; no dependencies, nothing to install).
- No private key, no signing, no wallet connection. Read-only.
- `--tokens` limits the scan to named tokens from the built-in list;
  `--spenders` replaces the spender list with addresses you supply
  (useful for checking approvals to a specific project contract).
- `node test-classify.mjs` runs the self-test for the classification
  logic (synthetic inputs, clearly labeled — see the file header).

## What it cannot do

- **It cannot see approvals to spenders outside its lists.** The matrix
  only probes spenders it knows. Full discovery needs the Approval event
  history, and public BSC RPCs refuse `eth_getLogs` — that is the
  tool's honest, documented limitation (see `DESIGN.md`).
- **It cannot verify a contract's intent.** `KNOWN-SAFE` means "this is
  the contract we think it is, and it is a well-known protocol" — not
  "this contract can never hurt you." Even famous contracts get
  upgraded or exploited.
- **It covers ERC-20 approvals only.** ERC-721 `setApprovalForAll`
  (marketplace approvals) is a separate, equally important surface.
- **It does not revoke anything.** Revoke calldata is printed; acting
  on it is the user's decision, in their own wallet.

## How the lists were built

Every address in the built-in lists was verified on-chain before
shipping: token addresses come from PancakeSwap's public token list and
were re-checked with `symbol()`/`decimals()` calls; spender contracts
were checked with `getCode` plus identity calls (`factory()`, `WETH()`).
Several addresses remembered from memory turned out to be wrong
(truncated or outdated) and were corrected or dropped — the list only
contains what the chain confirmed. See `DESIGN.md` for the full story
and for why an allowlist must be maintained, not trusted blindly.

## License

MIT — see [LICENSE](LICENSE).
