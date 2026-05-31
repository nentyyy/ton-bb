# Bug Bounty Report — Unbounded Recursive-Descent Parsing in Tolk and FunC Compilers (Stack Exhaustion / DoS)

## Summary

The Tolk and FunC compiler front-ends use recursive-descent parsers with **no parse-depth limit** in the syntactic parser. A small, crafted source file with deeply nested expressions or types drives unbounded native recursion, exhausting the thread stack and crashing the compiler process (`SIGSEGV`). Any service that compiles untrusted contract source (e.g. a hosted contract verifier / build backend) can be denied service with a single small input.

## Severity

**LOW** — Denial of Service, bounded to off-chain tooling that voluntarily compiles attacker-supplied source. No consensus, node-availability, RCE, or fund-safety impact (validators/nodes do not compile source at runtime).

## Component

Smart-contract compiler front-ends: Tolk compiler, FunC compiler.

## Affected Files & Functions

| File | Function(s) |
|------|-------------|
| `tolk/ast-from-tokens.cpp` | `parse_expr75` (unary), `parse_expr100` (parenthesized), `parse_type_expression` / `parse_nested_type_list` (types) |
| `crypto/func/parse-func.cpp` | `parse_expr100` (parenthesized), `parse_type1` (types) |

## Root Cause

Classic recursive-descent parsing with no depth counter, no iterative fallback, and no stack guard. Recursion depth equals the nesting depth of attacker-controlled source. Only *semantic* recursion checks exist in the toolchains; nothing bounds *syntactic* nesting.

Most minimal trigger — Tolk unary parser self-recurses once per prefix operator:

```cpp
// tolk/ast-from-tokens.cpp — parse_expr75 (parse ! ~ - + E)
static AnyExprV parse_expr75(Lexer& lex) {
  TokenType t = lex.tok();
  if (t == tok_logical_not || t == tok_bitwise_not || t == tok_minus || t == tok_plus) {
    ...
    lex.next();
    AnyExprV rhs = parse_expr75(lex);   // direct self-recursion, 1 frame per '-' '+' '~' '!'
    ...
  }
  ...
  return parse_expr80(lex);
}
```

Same class via the precedence cascade and type parsers:

```cpp
// tolk/ast-from-tokens.cpp — parse_expr100
case tok_oppar: {
  ...
  AnyExprV first = parse_expr(lex);   // full precedence descent per '('
```

```cpp
// crypto/func/parse-func.cpp — parse_expr100
Expr* res = parse_expr(lex, code, nv);  // recurses per '(' in FunC
```

```cpp
// crypto/func/parse-func.cpp — parse_type1
lex.expect('(');            // or '['
...
auto t1 = parse_type(lex);  // parse_type -> parse_type1 recurses per nested '(' / '['
```

## Technical Analysis

Each recursive frame carries non-trivial locals (AST smart pointers, `SrcRange`, lexer state), so an 8 MB thread stack is exhausted well before any semantic limit. A source of a few hundred KB can reach tens of thousands of levels. The result is a reliable stack overflow → `SIGSEGV` on the guard page.

This is a crash, not a memory-corruption primitive on platforms with a stack guard page (Linux/macOS default): the overflow hits the guard page and the process terminates rather than overwriting adjacent memory.

## Impact

DoS of the compiler process. In a hosted verification/build service that compiles user-submitted source, a single small crafted file crashes the worker; repeated submissions deny service to legitimate users.

Not reachable on validators/full nodes/lite servers — they execute compiled TVM bytecode and never compile source at runtime. No consensus or fund-safety impact.

## Reproduction Steps

1. Generate a malicious Tolk source: a function body `return ` followed by ~500,000 `-` characters, then `1;`.
2. Invoke the Tolk compiler on the file.
3. Observe `SIGSEGV` from stack exhaustion in `parse_expr75`.
4. Analogously for FunC: nested `(` in an expression (`parse_expr100`) or nested `(`/`[` in a type annotation (`parse_type1`).

Example generator:

```bash
python3 -c "open('poc.tolk','w').write('fun f(): int { return ' + '-'*500000 + '1; }')"
# then compile poc.tolk with the Tolk compiler
```

## Proof of Concept Strategy

- Emit a source file with N levels of nesting (start N ≈ 100,000 and bisect).
- Run under a debugger; confirm the crash is a stack overflow and the backtrace shows the parser function recursing to the stack limit.
- Optionally run under AddressSanitizer to confirm `stack-overflow` (not heap/global corruption).

## Suggested Fix

Add an explicit parse-depth bound (or make the hot precedence levels iterative):

- Maintain a depth counter incremented on entry to `parse_expr*` / `parse_type*` and decremented on exit; emit a normal parse error when a sane maximum (e.g. a few thousand) is exceeded.
- Apply identically in `tolk/ast-from-tokens.cpp` and `crypto/func/parse-func.cpp`.

This converts an uncontrolled crash into a clean, recoverable compile-time error.

## Confidence

HIGH that the bug is real and reachable (no depth guard exists; `parse_expr75` self-recursion verified directly in source). LOW severity in TON's deployment model.

## Self-Review

- **Can it happen?** Yes — recursive descent with no depth limit, verified in source.
- **Reproducible?** Yes — deterministic stack overflow from a small nested input.
- **External attacker?** Only where a service compiles attacker-supplied source (e.g. hosted verifier); not on a validator/node.
- **Unrealistic assumptions?** No for tooling; the impactful target is a specific deployment.
- **Merely theoretical?** No — concrete, reproducible crash. Not memory-corruption or consensus.
- **Maintainer view?** Likely a low-severity hardening/DoS fix for tooling.
- **Measurable impact?** Yes — process crash (DoS), bounded to off-chain compilation services.

## Audit Context

Reviewed against upstream TON commit `200a6e6794510be5d5faa83b15004bb3b135e7af` (working tree byte-identical to upstream). This was the only confirmed real finding across an audit covering ADNL/TL, catchain/validator-session, TVM/BOC, overlay/RLDP/RLDP2/DHT/FEC, lite-server/external-messages, decompression, the compiler toolchain, storage/torrent, and block validation (validate-query/transaction/block/mc-config) plus proof/signature verification. All other candidates were either properly guarded, gated behind privileged masterchain config, or deterministically harmless.
