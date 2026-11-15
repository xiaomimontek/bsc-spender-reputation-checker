# Design note — BSC Spender Reputation Checker

## Why the spender is the right unit of trust

A token approval is a triple: (owner, token, spender) → amount. Most
approval checkers present it grouped by token: "you approved WBNB to 3
contracts." That answers the wrong question. The token is just the asset
at risk; the spender is the party holding the key. One unlimited approval
to a malicious contract drains everything that token, while ten approvals
to well-known routers are routine. So this checker groups by spender and
classifies the spender — the token is context, the spender is the verdict.

This also matches how approvals actually go wrong. The two common failure
modes are both about the spender, not the token:

1. **The spender was never legitimate.** Approval phishing tricks a user
   into approving a contract the attacker controls. The token is
   irrelevant — any token approved to that address is gone.
2. **The spender stopped being trustworthy.** A legitimate contract gets
   abandoned, its keys leak, or an upgrade changes its behavior. The
   approval outlives the trust. This is the "dormant" case, and it is
   the hardest to catch, because nothing about the approval itself
   changed — only the world around it did.

## The allowlist, and its limits

The checker classifies spenders against a curated allowlist of known-safe
contracts. An allowlist is the only honest way to say "safe": a denylist
can only name yesterday's scams. But an allowlist has three limits the
user must understand:

- **It is incomplete by construction.** New legitimate contracts appear
  constantly. An unlisted contract is not guilty — it is *unverified*,
  which is why the checker says UNKNOWN, not MALICIOUS. The distinction
  matters: flagging everything unknown as malicious would train users to
  ignore the tool.
- **It goes stale.** A contract that was safe can stop being safe. The
  list needs maintenance: someone must re-verify entries, remove dead
  projects, and add new ones. A list nobody maintains becomes a false
  sense of security. This repo's list is small on purpose — four entries
  that were verified on-chain at build time — rather than a long list of
  addresses copied from memory.
- **It is opinionated.** "Known-safe" is a judgment, not a proof. The
  list names well-known protocols (a major DEX router, an aggregator,
  two ecosystem engines the author has used). Users who disagree should
  edit the list — it is a plain array at the top of `checker.mjs`, and
  `--spenders` lets anyone check approvals to contracts they name.

While building this, verification caught real errors: several token
addresses recalled from memory were truncated or outdated (BUSD, CAKE,
BTCB, DAI, FDUSD, DOGE, ADA, UNI, TUSD all needed correction). The
lesson is in the code: every address ships only after an on-chain check
(`getCode` + `symbol()`/`decimals()`/`factory()`), and the token
addresses were cross-checked against PancakeSwap's public token list.
Memory is not a source of truth; the chain is.

## Discovery under hostile infrastructure

The ideal discovery method is the event log: scan `Approval` events
where the wallet is the owner, and you learn every (token, spender)
pair ever approved, with no prior knowledge. In practice, every public
BSC RPC reachable from this environment refuses `eth_getLogs` — "limit
exceeded" even for a 100-block range, with or without an address filter.
Ankr requires authentication, NodeReal returns HTML, and the dataseed
hosts rate-limit aggressively.

So the checker uses a second method as its primary: the allowance-probe
matrix. For every (token, spender) pair in its curated lists it calls
`allowance(owner, spender)` via `eth_call`, which public nodes answer
reliably. A non-zero allowance is a real, currently-active approval —
no history needed, no logs needed. The cost is coverage: the matrix can
only find approvals to spenders already on the list. The checker attempts
the log scan anyway (best effort, small window), and when it is refused
it records that in the report instead of silently pretending the matrix
is complete. A security tool that hides its blind spots is worse than
one that admits them.

## Risk score

`riskScore` is deliberately simple and documented, so a user can argue
with it:

| Signal | Points |
|---|---|
| Unlimited approval (`2^256-1`) | +35 |
| UNKNOWN spender | +25 |
| DORMANT (unverifiable) spender | +20 |
| Spender is an EOA, not a contract | +15 |
| Stale approval (holds none of the token) | +10 |

Capped at 100. Bands: 0 CLEAN, 1–39 LOW, 40–69 MEDIUM, 70+ HIGH. The
weights encode a judgment: an unlimited approval is the single most
dangerous fact, and an unverifiable spender is worse than an unknown one
with a name. The score is a triage aid, not a verdict — a single
unlimited approval to an unknown contract (60, MEDIUM) deserves a look
even though the number is not "high".

## What a zkVerify proof could add (future work, not implemented)

An audit claim — "wallet X has no unlimited approvals to unverified
spenders" — is currently just words in a report. A zkVerify proof could
make it checkable: the checker would generate a Groth16 proof that its
classification procedure ran over a stated (token, spender) list and a
stated block, and that the resulting risk score is what it claims. A
third party could verify the proof against the registered verification
key without re-running the scan or trusting the report file.

That is future work for two honest reasons. First, the claim's strength
is bounded by the discovery limitation above — a proof over the matrix
proves "no approvals to *these* spenders", not "no approvals at all",
and a proof must not be sold as stronger than its inputs. Second, the
circuit and key registration are a separate build (Circom circuit over
the classification rule, proof submission via Kurier/zkVerifyJS, finality
before the claim is quoted). This design note states the direction; the
code does not pretend it exists.

## What this tool deliberately does not do

- No private keys, no signing, no transactions. Ever. The revoke
  calldata it prints is data, not an action.
- No paid APIs, no API keys. Everything is public RPC + public lists.
- No claim of completeness. The report's `discovery.limitation` field
  states the coverage gap in plain language, and the human output
  repeats it when no approvals are found.
