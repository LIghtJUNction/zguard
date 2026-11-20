# Validation map

The design has five parts: immutable policy, structured request binding, host
approval, bounded per-session state, and an execution audit boundary.

| Claim | Evidence | Scope |
| --- | --- | --- |
| Default deny and deterministic precedence | empty/unknown, namespace, all-order rule tests | Exact kind/name policies |
| Model input grants no authority | forged approval/capability/annotation test | Host-owned Context and Policy |
| Exact, single-use approval | changed bytes/ID/kind/name/argv/cwd/policy/context tests; compile-fail examples | In-process Rust ownership |
| Limits cannot be overridden | zero/boundary/over-limit/pending approval and counter overflow tests | Calls and payload bytes |
| Audit failure stops permission | sink failure, sequence and no-effect tests | Synchronous Audit contract |
| Request contents omitted | audit and Debug privacy tests | zguard-provided values |
| No standard library or allocator | bare-metal target compile; crate uses core only | Library implementation |
| No Cargo dependencies | cargo metadata dependency assertion | Published crate |
| Low state overhead | policy bench prints type sizes and measured operations | Stated target/build only |

Run python3 scripts/check.py for the host validation gate. The release workflow
also checks a target without std and runs the host gate on Linux, Windows and
macOS. A cross-target compile checks portability; a native runner checks runtime
tests on that operating system.

The benchmark uses three exact rules and a no-op audit sink. It measures pure
evaluation, authorization with no recording, and approval issuance plus
authorization. It excludes tool execution, real audit I/O and model latency.
Report optimized release results and the compiler/target with every measurement.

## Review questions

- Does every security claim map to an enforced branch and a negative test? Yes:
  the table names the corresponding test families.
- Are trusted host inputs distinct from model inputs? Yes: policy/context and
  approval creation belong to the host; request payloads remain opaque.
- Can approval bypass denial or resource constraints? No: constraints are
  reevaluated before approval binding, and tests cover quota/byte changes.
- Does the implementation promise isolation or durable identity? No: those
  responsibilities are explicit in SECURITY.md.
- Are performance and platform claims bounded by measurements? Yes: benchmark
  inputs and execution mode must accompany results; native results and target
  compilation are recorded separately.
