# PoC — Duplicate-orderId deposits merging into one order address (Relay, audit ronde 3)

**Result: the merge window R2 closed is OPEN again — the deployed oracle has
upgraded past SDK 0.0.133 to the simple `getOrderAddress(chainId, depositId)`.
Mechanism CONFIRMED live on-chain + in Foundry. Verdict: SUBMITTABLE (weak–moderate)
as S2/L1 — see below and `audit-relay-sdk-watch-r3.md`.**

Finding under test: `audit-relay.md` Finding 2 — two deposits sharing one
`orderId` mint to the same Hub `orderAddress`, and one `RelayExecutor.execute()`
sweeps the combined balance, capturing the second deposit's full value.

## What changed in round 3

Round 2 killed this finding because the deployed oracle pinned SDK 0.0.133,
whose `getOrderAddress` hashes `(chainId, depositor, timestamp, depositId)` —
a merge needed the same depositor AND the same block timestamp. Round 3 proves
the deployed oracle no longer runs that code:

- **Live on-chain proof:** a real Base USDC deposit
  (tx `0x96f02a79...`, depositId `0xc2c57705...`) minted to
  `0x543d3b0fff830bf0cb3a89f3e09d586461d8a9d0`, which equals
  `keccak256(abi.encode("base", depositId))` exactly; the 0.0.133 formula gives
  a different address. Scale check: **1120/5155** recent Base deposits match
  the simple formula, **0** match the old one.
- SDK timeline: the simple formula was promoted to `getOrderAddress` in
  **0.0.140 (2026-09-09)** (0.0.139 only added it as `getOrderAddressV2`).
  Latest published SDK is 0.0.156.
- This PoC is the round-2 PoC with LEG 2 adapted to the live formula
  (see test names below). Round-2 PoC kept intact at
  `../poc-relay-duplicate-orderid/`.

## How to run

```bash
export PATH="$HOME/.foundry/bin:$PATH"   # forge 1.9.0
cd ~/workspace/bounty-hunt/poc-relay-duplicate-orderid-r3
forge test
```

No fork, no RPC URL, no funds, no network. Clean `rm -rf out cache && forge test`:
**5 passed, 0 failed.** Real, unmodified Relay contracts (`src/` is a verbatim
copy of `RelayHub`, `RelayAllocator`, `RelayExecutor`, `Utils`, `ERC20View`,
`ICallResolver` from `relay-settlement-main/smart-contracts/contracts/`,
vendored forge-std 1.9.0 + only the 20 imported OpenZeppelin 5.3.0 contracts
— same trimmed layout as `poc-relay-executor`).

## What the tests prove

| Test | Result |
|---|---|
| `test_duplicateDepositMergedAndSweptByFirstExecution` | Two 1000 deposits minted to one order address; one execution returns only the signed 950 minimum; resolver keeps **1050**; order drained. Second deposit's **full 1000 lost** to its depositor. |
| `test_orderAddressIgnoresDepositorAndTimestamp` (NEW, r3) | Same `depositId`, different block timestamp → **same** order address. Same `depositId`, different depositor → **same** order address. Different `depositId` → different address. |
| `test_crossTxDuplicateMergedAndSwept` (NEW, r3) | Duplicate deposit in a LATER block now merges to the same order address and **is swept** by the first order's execution (resolver keeps 1050). Round 2's `test_retryInLaterBlockNotSwept` asserted the opposite and is replaced. |
| `test_attackerSelfDepositIsProfitNeutral` | Attacker deposits own 1000 into victim's order address, executes with own resolver → net **+50, exactly the honest solver spread**. Zero extra profit. |
| `test_honestSingleDepositControl` | Single 1000, honest resolver → full 1000 withdrawn, attacker 0. |

## Verdict (round 3): SUBMITTABLE as S2/L1 — weak–moderate, do NOT file as S1

- **Mechanism: live, not theoretical.** The deployed oracle demonstrably
  computes order addresses with the simple formula (on-chain proof above),
  and the merge + sweep is reproduced here on real contracts.
- **Impact if triggered:** full loss of the duplicate deposit to the
  executing resolver (1000 of 1000 in the PoC).
- **Likelihood: L1.** No attacker path — self-deposit stays profit-neutral,
  and an attacker cannot force a victim to reuse an `orderId`. The trigger is
  victim/integrator reuse of an orderId (retry / double-submit / integrator
  bug). In a 10h sample of 5178 Base event-deposits, **zero** duplicate
  depositIds were observed, and no live victim loss has been observed yet.
  Filing as S1 would overclaim.
- **What would lift it to L2:** one observed live duplicate depositId with a
  double-mint, or an integrator that systematically reuses orderIds.
  Open watch items are in `audit-relay-sdk-watch-r3.md` §6–§7.

## The old (round 2) correction — now superseded

Ronde 1 assumed `getOrderAddress() = keccak256(abi.encode(chainId, depositId))`
from monorepo `main` SDK. Ronde 2 corrected that the deployed oracle pinned
`@relay-protocol/settlement-sdk@0.0.133`
(`relay-protocol-oracle-main/package.json:31`), whose formula included
depositor+timestamp — so the merge needed same depositor AND same block
timestamp, and the finding was not submittable. **That correction is now
itself outdated:** the deployed oracle has moved past 0.0.133 (its live
`IMAGE_TAG` is a SHA absent from the public oracle repo, whose `main` is
frozen since 2026-08-12), and its order addresses follow the simple formula.
