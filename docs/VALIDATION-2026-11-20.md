# Local validation — 2026-11-20

## Verified source and environment

Core source: commit `6cb85619bb948fd103a9a440054849be71cbb238`.
The checks ran on x86_64 Linux with Rust 1.100.0
(`0ef1bc386059596dada8fb65b50425aab2ea637a`, LLVM 23.1.5),
on an Intel Core i9-12900HX. No credentials or live model service were involved.

The host gate passed 26 runtime tests and three doctests, including two compile
failures that enforce Approval ownership. It also passed strict Clippy,
formatting, the example executor counter and a Cargo metadata assertion that
the crate has zero dependencies.

The following library target checks passed:

| Target | Validation |
| --- | --- |
| `x86_64-unknown-none` | Bare-metal no_std compile, without a standard library |
| `wasm32-unknown-unknown` | Wasm library compile |
| `x86_64-pc-windows-gnu` | Windows library cross-compile |
| `aarch64-apple-darwin` | macOS arm64 library cross-compile |

These target checks do not execute Windows or macOS programs. The formal
release workflow has separate native Linux, Windows and macOS test jobs.

## Optimized microbenchmark

Command: `cargo bench --locked --bench policy`. Each row used 10,000 warm-up
operations and 1,000,000 measured operations. The benchmark had three exact
rules, caller-owned request slices and NoAudit. Black-box inputs and outputs
preserve the measured work.

| Operation | One-run mean |
| --- | ---: |
| Policy evaluation | 16.31 ns |
| Authorization and quota reservation, NoAudit | 17.36 ns |
| Approval issuance plus authorization, NoAudit | 64.98 ns |

These are one run's measurements on a shared development machine. They measure
the policy core, not audit I/O, plugin execution, network latency or model
inference. They are useful for reproducing this workload, not a promise for
other machines or rule sets.

Type sizes on this 64-bit target:

| Value | Bytes |
| --- | ---: |
| Guard | 88 |
| Rule | 32 |
| AuditEvent | 48 |
| Approval | 112 |

Borrowed rules and payload buffers remain owned by the application. The sizes
above describe the values themselves, not all application memory.

## Security evidence

The runtime tests cover default rejection, exact names and namespaces, every
ordering of allow/approval/deny, required capability unions, forged model
approval fields, exact JSON bytes, call IDs, structured argv and cwd, complete
policy and context binding, expiry, clock regression, quotas and byte limits,
audit failure, redacted debug output, and counter overflow. Rejected execution
examples leave the side-effect counter at zero.
