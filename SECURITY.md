# Security contract

## Trusted host and untrusted requests

The host is the enforcement boundary. It authenticates the operator, registers
tools, assigns capability bits, chooses immutable policy rules, owns the clock
and calls the executor only after an allowed verdict. The AI may propose names
and arguments; those values do not change policy or create approval objects.

Each tool's implementation defines its real effects. zguard deliberately keeps
payloads opaque, so an allowed broad shell, network or native plugin adapter can
exercise everything that adapter exposes. The host must validate arguments,
resolve resource identity and provide process or Wasm isolation where required.
Remote annotations are untrusted unless the host establishes their provenance,
as required by the [MCP tool specification](https://modelcontextprotocol.io/specification/2025-11-25/server/tools).

## Policy and approval

A policy is immutable for its borrowed lifetime. Exact kind/name matches combine
capability requirements. Deny overrides approval and allow; approval overrides
allow. Approval never overrides invalid requests, missing capabilities, input
limits, exhausted call quotas or an explicit deny.

An approval binds the complete policy value, including every rule and its order,
host context, request ID, action kind, name, payload and expiry. Raw JSON bytes
are compared exactly. Command argv is compared as a sequence and cwd separately.
This avoids concatenation ambiguities such as `["ab", "c"]` and `["a", "bc"]`.
Equivalent policies reordered after approval are conservatively rejected.

The approval Rust object is consumed by one authorization attempt. This also
applies to mismatch, expiry, clock regression or audit failure. A trusted host
can deliberately issue another approval. The library does not authenticate a
human, sign a transferable token or persist replay state across crashes.

Identical policy and context values intentionally describe the same domain.
Use a fresh session epoch when recreating a guard, restoring a process or
changing trust. A different session, capability mask, policy revision or rule
set rejects an earlier approval. Time uses one host-supplied monotonic domain;
expiry is exclusive and clock regression is denied.

## Quota and execution

Authorization reserves one call only after the configured audit sink accepts
the event. Each successful authorization consumes quota regardless of the
executor's result. There is no automatic retry or refund. A host must authorize
each attempted retry and avoid reusing an allowed verdict for another effect.

Mutable guard access serializes its quota reservation. Separate guard instances
have separate quotas; sharing a numeric session ID does not share counters.
The host owns scheduling, synchronization, cancellation and distributed limits.

Payload limits describe input byte counts. They do not cap total process memory,
argument descriptor counts, output size, elapsed time, policy-rule count or
external resource consumption. Rule lists and request slices remain caller-owned.

## Audit and privacy

Audit events omit raw payload, names, call IDs, command lines and output. They
contain numeric context/policy/sequence IDs, kind, byte length and verdict.
Request and Approval Debug implementations also omit request contents.
Numeric IDs and lengths may still reveal operational metadata; the host applies
its retention and access policy.

Audit rejection returns Deny/AuditFailed without reserving a call. The sequence
advances before recording, so a failed attempt is not silently assigned the same
sequence as a later attempt. An Allow audit event describes the decision before execution, not its result.
The host records executor outcomes separately. Successful recording means only the sink accepted
the event; the sink owns durable storage and tamper protection. NoAudit is an
explicit host opt-out.

The core is safe Rust with no allocator or Cargo dependencies. Trusted host
callbacks can allocate, panic or perform I/O. Panics are not caught, and a malicious
host can bypass any library API. The library provides deterministic policy
checks, not an operating-system sandbox or semantic prompt-injection detector.

## Reporting

Report a vulnerability with a minimal reproduction and the affected version
through the repository's private security reporting channel when available.
Do not include production credentials, private prompts or user data in public
issues. The abuse tests in tests/guard.rs document the intended enforcement
semantics.
