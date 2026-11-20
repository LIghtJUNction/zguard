# zguard

**Lightweight Security Guardrails for AI Agents.**

zguard makes an explicit decision before an AI tool or command is executed. It
matches host-owned policies, checks capability and input limits, consumes exact
request approvals, and records a bounded audit event before reserving a call.
The library is `no_std`, uses no allocator, has no Cargo dependencies, and forbids
unsafe Rust.

## Use

```toml
[dependencies]
zguard = "=0.1.0"
```

```rust
use zguard::{ActionKind, Context, Decision, Guard, Limits, NoAudit, Policy, Request, Rule};

let rules = [
    Rule::new(1, ActionKind::Tool, "files.read", Decision::Allow).requiring(1),
    Rule::new(2, ActionKind::Tool, "files.write", Decision::RequireApproval).requiring(2),
    Rule::new(3, ActionKind::Tool, "shell.run", Decision::Deny),
];
let policy = Policy::new(7, &rules)?;
let mut guard = Guard::new(
    policy,
    Context { session: 42, capabilities: 3 },
    Limits { max_calls: 20, max_payload_bytes: 4096 },
);
let request = Request::tool("call-1", "files.read", br#"{"path":"notes.txt"}"#);
let verdict = guard.authorize(request, 100, None, &mut NoAudit);
assert!(verdict.is_allowed());
// Invoke the trusted executor now, with this exact request.
// For production audit, replace NoAudit with your Audit implementation.
# Ok::<(), zguard::PolicyError>(())
```

The host owns the executor, identity, session epoch, policy, monotonic clock and
approval channel. Construct capability masks from authenticated host state.
Model arguments and remote tool annotations are request data and grant no rights.
[MCP documents this trust boundary for tool annotations](https://modelcontextprotocol.io/specification/2025-11-25/server/tools).

## Decisions and limits

Names match exactly and case-sensitively. Tool and command namespaces are
separate. Unknown names and an empty policy are denied. When several rules match,
explicit deny wins, then approval, then allow; the smallest relevant rule ID
makes audit results deterministic. All matching capability requirements combine.

`RequireApproval` stops execution. After its external approval process, the host
calls `Guard::approve(request, expires_at)` and passes the returned object to
`authorize`. Approval binds the complete immutable policy and context, call ID,
kind, name and raw tool bytes or structured command argv/cwd. A mismatched,
expired or consumed object grants nothing. Expiry is exclusive: `now >= expires_at`
is expired. Clock values may stay equal and must never decrease.

The approval object is not cloneable and is consumed on every authorization
attempt, including rejected attempts. The trusted host can issue a new object.
Use a fresh session epoch when recreating a guard; equal policy/context values
deliberately describe the same authorization domain. Tokens are process-local
Rust values, not signed credentials or persistent replay protection.

Limits cap authorized attempts and each request's payload bytes. Tool bytes are
counted verbatim. Command bytes sum argv and cwd UTF-8 lengths; argv boundaries
remain separate for approval matching. An allowed call reserves one quota unit
after audit succeeds and before execution. Failed executors do not refund it.
The host must count any retry as another authorization attempt.

## Audit and execution boundary

`Audit::record` receives numeric session/policy/sequence IDs, action kind, payload
length and a verdict. It receives no arguments, command lines, names, call IDs or
outputs. A sink error changes the returned verdict to `Deny / AuditFailed` and
does not reserve a call. The sequence still advances, identifying the attempted
decision. The sink controls durability, transport and access to records.

Only `authorize(...).is_allowed()` permits an effect. `evaluate` is a pure preview.
Place authorization immediately before the executor and use the same request
without mutation or substitution. zharness integrates this boundary through its
native guarded execution APIs. Direct application executors remain trusted code.

## Scope

zguard evaluates deterministic host policy. The host provides JSON validation,
argument/resource policy, OS isolation, canonical paths, network controls and
execution timeouts. Authorizing a general shell or plugin grants the capabilities
that its adapter exposes. Use narrow tools and OS isolation where required.
Natural-language prompt-injection detection is outside this core.

## Validate

```sh
python3 scripts/check.py
cargo bench --locked --bench policy
cargo check --locked --lib --target x86_64-unknown-none
```

The final command requires that Rust target to be installed. See
[SECURITY.md](SECURITY.md) for trust and approval contracts and
[docs/VALIDATION.md](docs/VALIDATION.md) for claim-to-evidence mapping.

The first local validation and optimized measurements are recorded in
[docs/VALIDATION-2026-11-20.md](docs/VALIDATION-2026-11-20.md).

[Release instructions](docs/RELEASING.md) describe immutable tags and verified
registry/GitHub recovery.
