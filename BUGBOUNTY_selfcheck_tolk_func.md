# TON Bug Bounty Self-Check — Tolk/FunC Parser Recursion

**Skill applied:** https://github.com/ton-blockchain/bug-bounty/blob/main/skills/bug-bounty-self-check.md
**Report under review:** `BUGBOUNTY_tolk_func_parser_recursion.md`

## VERDICT: ⛔ DO NOT SEND (status: NOT correct)

This report does **not** pass the self-check as-is. Two blocking gaps and an unresolved scope question. Details below, checklist item by item.

---

## 1. Scope & Eligibility — ❓ UNRESOLVED (blocking)
- The Tolk/FunC compilers are **off-chain developer tooling**. They are not the node, validator, TVM runtime, ADNL/overlay stack, or on-chain smart contracts.
- TON's bounty scope centers on components whose compromise affects the network, consensus, or funds. A compiler crash that only affects a process voluntarily compiling untrusted source may be **out of scope** or redirected (the skill notes frontend → HackenProof, third-party/tooling → owners).
- **Action required:** confirm against the current in-scope list before submitting. If compiler tooling is not explicitly in scope, the report is ineligible.

## 2. Technical Validation — ✅ MOSTLY PASS
- Exact files/functions identified: `tolk/ast-from-tokens.cpp` (`parse_expr75`, `parse_expr100`, `parse_type_expression`/`parse_nested_type_list`), `crypto/func/parse-func.cpp` (`parse_expr100`, `parse_type1`). ✅
- Exists in latest relevant code: yes — working tree byte-identical to upstream `200a6e6` (current HEAD). ✅
- Not already fixed: confirmed — grep shows no depth/recursion/nesting guard in either parser. ✅
- Realistic attacker-controlled input path: **conditional** — only a service that compiles untrusted source. On a node/validator there is no such path. ⚠️
- Conditions actually trigger the bug: analytically yes (no depth bound), but **not empirically demonstrated** — see item 3.

## 3. Reproducibility Evidence — ⛔ FAIL (blocking)
- The skill requires, for crashes, **actual reproduction and `ton-bug-triage` artifacts**.
- This report provides only repro *steps* and a PoC *strategy* — **no compiled binary was run, no crash/SIGSEGV was observed, no triage artifact (backtrace, ASan output) is attached.**
- Until the crash is actually reproduced against a built Tolk/FunC compiler and an artifact captured, the evidence requirement is not met.

## 4. Report Completeness — ✅ PASS
- Title, summary, component, affected commit (`200a6e6`), files/functions, prerequisites, trigger conditions, repro steps, expected/actual, remediation present. ✅
- (Expected/actual results could be stated more explicitly, but structurally complete.)

## 5. Common Errors — ⚠️ PARTIAL RISK
- "Don't overstate DoS impact" — OK: rated LOW honestly. ✅
- "Don't submit generic crashes without security explanation" — **risk**: a parser stack-overflow in dev tooling is close to a generic crash; the security narrative (hosted verifier DoS) is plausible but thin. ⚠️
- "Don't rely on modified binaries/debug-only conditions" — OK: stock code. ✅
- "Don't report known design peculiarities" — **risk**: unbounded recursive descent may be considered a known limitation rather than a vulnerability. ⚠️

## 6. Smart Contract Specifics — N/A
- Not a smart-contract/action-phase issue.

---

## What must happen before this could be sent
1. **Confirm scope:** verify compiler tooling is in-scope per current TON bounty rules. If not → do not submit.
2. **Produce real evidence:** build the Tolk/FunC compiler, run the crafted nested-input PoC, capture the SIGSEGV backtrace / `ton-bug-triage` artifact (and/or ASan `stack-overflow`).
3. **Sharpen the security impact:** identify a concrete in-scope service that compiles untrusted source, or accept that impact is tooling-only.

If 1 or 2 cannot be satisfied, the honest outcome is **do not submit** — this is a low-severity tooling hardening item, not a network/consensus/fund vulnerability.
