#![no_std]
#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

use core::fmt;

/// Execution namespace; command grants never grant a tool of the same name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActionKind {
    Tool,
    Command,
}

/// Only Allow authorizes an invocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[must_use]
pub enum Decision {
    Allow,
    Deny,
    RequireApproval,
}

/// Stable, bounded explanations. No argument data is retained.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Reason {
    Allowed,
    ExplicitDeny,
    ApprovalRequired,
    ApprovalNotRequired,
    Approved,
    NoMatchingRule,
    MissingCapabilities,
    PayloadLimit,
    CallLimit,
    InvalidRequest,
    ApprovalMismatch,
    ApprovalExpired,
    InvalidExpiry,
    ClockRegressed,
    AuditFailed,
    SequenceExhausted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[must_use]
pub struct Verdict {
    pub decision: Decision,
    pub reason: Reason,
    pub rule_id: Option<u32>,
}
impl Verdict {
    pub const fn is_allowed(self) -> bool {
        matches!(self.decision, Decision::Allow)
    }
    const fn deny(reason: Reason, rule_id: Option<u32>) -> Self {
        Self {
            decision: Decision::Deny,
            reason,
            rule_id,
        }
    }
}

/// A host-authored rule with exact, case-sensitive name matching.
/// Requirements of all matching rules are combined; a permissive rule cannot
/// bypass another matching rule's capability requirement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Rule<'a> {
    id: u32,
    kind: ActionKind,
    name: &'a str,
    decision: Decision,
    capabilities: u64,
}
impl<'a> Rule<'a> {
    pub const fn new(id: u32, kind: ActionKind, name: &'a str, decision: Decision) -> Self {
        Self {
            id,
            kind,
            name,
            decision,
            capabilities: 0,
        }
    }
    pub const fn requiring(mut self, capabilities: u64) -> Self {
        self.capabilities = capabilities;
        self
    }
    pub const fn id(self) -> u32 {
        self.id
    }
    pub const fn kind(self) -> ActionKind {
        self.kind
    }
    pub const fn name(self) -> &'a str {
        self.name
    }
    pub const fn decision(self) -> Decision {
        self.decision
    }
    pub const fn capabilities(self) -> u64 {
        self.capabilities
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyError {
    InvalidName { rule_id: u32 },
    DuplicateRuleId { rule_id: u32 },
}
impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl core::error::Error for PolicyError {}

/// Immutable host policy. Use a distinct ID for each policy revision in audits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Policy<'a> {
    id: u64,
    rules: &'a [Rule<'a>],
}
impl<'a> Policy<'a> {
    pub fn new(id: u64, rules: &'a [Rule<'a>]) -> Result<Self, PolicyError> {
        for (index, rule) in rules.iter().enumerate() {
            if !valid_name(rule.kind, rule.name) {
                return Err(PolicyError::InvalidName { rule_id: rule.id });
            }
            if rules[..index].iter().any(|other| other.id == rule.id) {
                return Err(PolicyError::DuplicateRuleId { rule_id: rule.id });
            }
        }
        Ok(Self { id, rules })
    }
    pub const fn id(self) -> u64 {
        self.id
    }
    pub const fn rules(self) -> &'a [Rule<'a>] {
        self.rules
    }
}

/// Trusted host data, never populated from model arguments/tool annotations.
/// Use a fresh session epoch when recreating a guard. IDs are not authentication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Context {
    pub session: u64,
    pub capabilities: u64,
}

/// Authorized attempts and per-request input bytes. Calls count before execution;
/// failed executors and retries are not refunded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    pub max_calls: u64,
    pub max_payload_bytes: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_calls: 128,
            max_payload_bytes: 65_536,
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Payload<'a> {
    Tool(&'a [u8]),
    Command {
        args: &'a [&'a str],
        cwd: Option<&'a str>,
    },
}

/// Exact borrowed request binding. argv boundaries and cwd remain structured;
/// no concatenation or hash identifies approvals. Debug omits request contents.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Request<'a> {
    call_id: &'a str,
    name: &'a str,
    payload: Payload<'a>,
}
impl<'a> Request<'a> {
    pub const fn tool(call_id: &'a str, name: &'a str, arguments: &'a [u8]) -> Self {
        Self {
            call_id,
            name,
            payload: Payload::Tool(arguments),
        }
    }
    pub const fn command(
        call_id: &'a str,
        program: &'a str,
        args: &'a [&'a str],
        cwd: Option<&'a str>,
    ) -> Self {
        Self {
            call_id,
            name: program,
            payload: Payload::Command { args, cwd },
        }
    }
    pub const fn kind(self) -> ActionKind {
        match self.payload {
            Payload::Tool(_) => ActionKind::Tool,
            Payload::Command { .. } => ActionKind::Command,
        }
    }
    pub const fn call_id(self) -> &'a str {
        self.call_id
    }
    pub const fn name(self) -> &'a str {
        self.name
    }

    /// Tool bytes, or summed command argument and cwd UTF-8 bytes.
    /// Names and IDs are structurally validated separately.
    pub fn payload_bytes(self) -> Option<usize> {
        match self.payload {
            Payload::Tool(bytes) => Some(bytes.len()),
            Payload::Command { args, cwd } => args
                .iter()
                .try_fold(cwd.map_or(0, str::len), |n, arg| n.checked_add(arg.len())),
        }
    }
    fn valid(self) -> bool {
        if self.call_id.is_empty()
            || self.call_id.contains('\0')
            || !valid_name(self.kind(), self.name)
        {
            return false;
        }
        match self.payload {
            Payload::Tool(_) => true,
            Payload::Command { args, cwd } => {
                !args.iter().any(|arg| arg.contains('\0'))
                    && !cwd.is_some_and(|path| path.is_empty() || path.contains('\0'))
            }
        }
    }
}
impl fmt::Debug for Request<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Request")
            .field("kind", &self.kind())
            .field("payload_bytes", &self.payload_bytes())
            .finish_non_exhaustive()
    }
}
fn valid_name(kind: ActionKind, name: &str) -> bool {
    !name.is_empty()
        && !name.contains('\0')
        && match kind {
            ActionKind::Tool => {
                name.len() <= 128
                    && name.is_ascii()
                    && !name.bytes().any(|b| b.is_ascii_control() || b == b' ')
            }
            ActionKind::Command => true,
        }
}

/// Synchronously recorded before allowed effects. Raw arguments, names, call IDs
/// and outputs are deliberately absent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuditEvent {
    pub session: u64,
    pub policy_id: u64,
    pub sequence: u64,
    pub kind: ActionKind,
    pub payload_bytes: usize,
    pub verdict: Verdict,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuditFailure;
impl fmt::Display for AuditFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("audit unavailable")
    }
}
impl core::error::Error for AuditFailure {}

pub trait Audit {
    /// Error prevents authorization. The host sink owns durability and integrity.
    fn record(&mut self, event: AuditEvent) -> Result<(), AuditFailure>;
}
impl<A: Audit + ?Sized> Audit for &mut A {
    fn record(&mut self, event: AuditEvent) -> Result<(), AuditFailure> {
        (**self).record(event)
    }
}

/// Explicit host opt-out. Choose a real sink when audit is required.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoAudit;
impl Audit for NoAudit {
    fn record(&mut self, _event: AuditEvent) -> Result<(), AuditFailure> {
        Ok(())
    }
}

/// Host-issued in-process approval consumed by one authorization attempt.
///
/// ~~~compile_fail
/// use zguard::Approval;
/// fn duplicate(approval: Approval<'_, '_>) { let _copy = approval.clone(); }
/// ~~~
///
/// ~~~compile_fail
/// use zguard::Approval;
/// fn consume(_: Approval<'_, '_>) {}
/// fn replay(approval: Approval<'_, '_>) { consume(approval); consume(approval); }
/// ~~~
/// It has no Copy/Clone/serialization implementation. A trusted host can issue
/// another approval; this object does not authenticate humans or survive crashes.
#[must_use]
pub struct Approval<'p, 'r> {
    policy: Policy<'p>,
    context: Context,
    request: Request<'r>,
    expires_at: u64,
}
impl fmt::Debug for Approval<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Approval")
            .field("policy_id", &self.policy.id)
            .field("session", &self.context.session)
            .field("kind", &self.request.kind())
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

/// Per-session state. Mutable access serializes authorization/quota reservation.
/// This core has no executor, allocator, worker, I/O or operating-system runtime.
#[derive(Debug)]
pub struct Guard<'p> {
    policy: Policy<'p>,
    context: Context,
    limits: Limits,
    calls: u64,
    sequence: u64,
    last_now: Option<u64>,
}
impl<'p> Guard<'p> {
    pub const fn new(policy: Policy<'p>, context: Context, limits: Limits) -> Self {
        Self {
            policy,
            context,
            limits,
            calls: 0,
            sequence: 0,
            last_now: None,
        }
    }
    pub const fn policy(&self) -> Policy<'p> {
        self.policy
    }
    pub const fn context(&self) -> Context {
        self.context
    }
    pub const fn limits(&self) -> Limits {
        self.limits
    }
    pub const fn calls(&self) -> u64 {
        self.calls
    }
    pub const fn remaining_calls(&self) -> u64 {
        self.limits.max_calls - self.calls
    }

    /// Pure preflight, not execution permission. Always authorize immediately
    /// before the real execution boundary.
    pub fn evaluate(&self, request: Request<'_>) -> Verdict {
        if !request.valid() {
            return Verdict::deny(Reason::InvalidRequest, None);
        }
        if request
            .payload_bytes()
            .is_none_or(|n| n > self.limits.max_payload_bytes)
        {
            return Verdict::deny(Reason::PayloadLimit, None);
        }
        if self.calls >= self.limits.max_calls {
            return Verdict::deny(Reason::CallLimit, None);
        }
        let (mut deny, mut approval, mut allow, mut first) = (None, None, None, None);
        let mut required = 0;
        for rule in self.policy.rules {
            if rule.kind != request.kind() || rule.name != request.name {
                continue;
            }
            required |= rule.capabilities;
            first = min_id(first, rule.id);
            let selected = match rule.decision {
                Decision::Deny => &mut deny,
                Decision::RequireApproval => &mut approval,
                Decision::Allow => &mut allow,
            };
            *selected = min_id(*selected, rule.id);
        }
        if let Some(id) = deny {
            return Verdict::deny(Reason::ExplicitDeny, Some(id));
        }
        if first.is_none() {
            return Verdict::deny(Reason::NoMatchingRule, None);
        }
        if self.context.capabilities & required != required {
            return Verdict::deny(Reason::MissingCapabilities, first);
        }
        if let Some(id) = approval {
            return Verdict {
                decision: Decision::RequireApproval,
                reason: Reason::ApprovalRequired,
                rule_id: Some(id),
            };
        }
        Verdict {
            decision: Decision::Allow,
            reason: Reason::Allowed,
            rule_id: allow,
        }
    }

    /// Trusted host entry after its external approval process. Denies,
    /// capability failures and quota failures cannot be overridden.
    pub fn approve<'r>(
        &self,
        request: Request<'r>,
        expires_at: u64,
    ) -> Result<Approval<'p, 'r>, Verdict> {
        let verdict = self.evaluate(request);
        if verdict.decision != Decision::RequireApproval {
            return Err(if verdict.is_allowed() {
                Verdict::deny(Reason::ApprovalNotRequired, verdict.rule_id)
            } else {
                verdict
            });
        }
        if expires_at <= self.last_now.unwrap_or(0) {
            return Err(Verdict::deny(Reason::InvalidExpiry, verdict.rule_id));
        }
        Ok(Approval {
            policy: self.policy,
            context: self.context,
            request,
            expires_at,
        })
    }

    /// Consume approval and record an audit before reserving one execution.
    /// Only Allow may invoke user code, immediately for this exact request.
    /// now is a trusted monotonic host clock; equal ticks are accepted.
    /// Every supplied approval is consumed even after denial or audit failure.
    pub fn authorize(
        &mut self,
        request: Request<'_>,
        now: u64,
        approval: Option<Approval<'_, '_>>,
        audit: &mut impl Audit,
    ) -> Verdict {
        let mut verdict = self.evaluate(request);
        if self.last_now.is_some_and(|prior| now < prior) {
            verdict = Verdict::deny(Reason::ClockRegressed, verdict.rule_id);
        } else {
            self.last_now = Some(now);
            if verdict.decision != Decision::Deny
                && let Some(approval) = approval
            {
                if approval.policy != self.policy
                    || approval.context != self.context
                    || approval.request != request
                {
                    verdict = Verdict::deny(Reason::ApprovalMismatch, verdict.rule_id);
                } else if now >= approval.expires_at {
                    verdict = Verdict::deny(Reason::ApprovalExpired, verdict.rule_id);
                } else {
                    verdict.decision = Decision::Allow;
                    verdict.reason = Reason::Approved;
                }
            }
        }
        let Some(sequence) = self.sequence.checked_add(1) else {
            return Verdict::deny(Reason::SequenceExhausted, verdict.rule_id);
        };
        self.sequence = sequence;
        let event = AuditEvent {
            session: self.context.session,
            policy_id: self.policy.id,
            sequence,
            kind: request.kind(),
            payload_bytes: request.payload_bytes().unwrap_or(usize::MAX),
            verdict,
        };
        if audit.record(event).is_err() {
            return Verdict::deny(Reason::AuditFailed, verdict.rule_id);
        }
        if verdict.is_allowed() {
            self.calls += 1;
        }
        verdict
    }
}
fn min_id(current: Option<u32>, candidate: u32) -> Option<u32> {
    Some(current.map_or(candidate, |id| id.min(candidate)))
}

#[cfg(test)]
mod counter_tests {
    use super::*;
    #[test]
    fn sequence_exhaustion_denies_without_wraparound() {
        let rules = [Rule::new(1, ActionKind::Tool, "read", Decision::Allow)];
        let mut guard = Guard::new(
            Policy::new(1, &rules).unwrap(),
            Context {
                session: 1,
                capabilities: 0,
            },
            Limits::default(),
        );
        guard.sequence = u64::MAX;
        let result = guard.authorize(Request::tool("a", "read", b"{}"), 1, None, &mut NoAudit);
        assert_eq!(result.reason, Reason::SequenceExhausted);
        assert_eq!(guard.calls(), 0);
        assert_eq!(guard.sequence, u64::MAX);
    }
    #[test]
    fn maximal_call_budget_has_no_wraparound() {
        let rules = [Rule::new(1, ActionKind::Tool, "read", Decision::Allow)];
        let mut guard = Guard::new(
            Policy::new(1, &rules).unwrap(),
            Context {
                session: 1,
                capabilities: 0,
            },
            Limits {
                max_calls: u64::MAX,
                max_payload_bytes: 100,
            },
        );
        guard.calls = u64::MAX - 1;
        let req = Request::tool("a", "read", b"{}");
        assert!(guard.authorize(req, 1, None, &mut NoAudit).is_allowed());
        assert_eq!(guard.calls(), u64::MAX);
        assert_eq!(
            guard.authorize(req, 1, None, &mut NoAudit).reason,
            Reason::CallLimit
        );
    }
}
