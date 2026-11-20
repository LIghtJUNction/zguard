use zguard::*;

fn guard<'a>(rules: &'a [Rule<'a>]) -> Guard<'a> {
    Guard::new(
        Policy::new(7, rules).unwrap(),
        Context {
            session: 11,
            capabilities: 3,
        },
        Limits::default(),
    )
}
fn tool<'a>(id: &'a str, name: &'a str, bytes: &'a [u8]) -> Request<'a> {
    Request::tool(id, name, bytes)
}
const ALLOW: Rule<'_> = Rule::new(1, ActionKind::Tool, "read", Decision::Allow);
const APPROVAL: Rule<'_> = Rule::new(2, ActionKind::Tool, "write", Decision::RequireApproval);
const DENY: Rule<'_> = Rule::new(3, ActionKind::Tool, "delete", Decision::Deny);

#[derive(Default)]
struct Log(Vec<AuditEvent>);
impl Audit for Log {
    fn record(&mut self, event: AuditEvent) -> Result<(), AuditFailure> {
        self.0.push(event);
        Ok(())
    }
}
struct Unavailable;
impl Audit for Unavailable {
    fn record(&mut self, _: AuditEvent) -> Result<(), AuditFailure> {
        Err(AuditFailure)
    }
}

#[test]
fn empty_policy_and_unknown_tools_fail_closed() {
    let mut empty = guard(&[]);
    assert_eq!(
        empty
            .authorize(tool("a", "read", b"{}"), 1, None, &mut NoAudit)
            .reason,
        Reason::NoMatchingRule
    );
    let mut g = guard(&[ALLOW]);
    for name in ["unknown", "Read", "read.extra", "read/child"] {
        assert_eq!(
            g.authorize(tool("a", name, b"{}"), 1, None, &mut NoAudit)
                .reason,
            Reason::NoMatchingRule
        );
    }
    assert_eq!(g.calls(), 0);
}

#[test]
fn command_and_tool_namespaces_are_distinct() {
    let mut g = guard(&[ALLOW]);
    let result = g.authorize(
        Request::command("a", "read", &[], None),
        1,
        None,
        &mut NoAudit,
    );
    assert_eq!(result.reason, Reason::NoMatchingRule);
}

#[test]
fn explicit_deny_wins_in_every_rule_order() {
    let variants = [
        Rule::new(1, ActionKind::Tool, "op", Decision::Allow),
        Rule::new(2, ActionKind::Tool, "op", Decision::RequireApproval),
        Rule::new(3, ActionKind::Tool, "op", Decision::Deny),
    ];
    for order in [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ] {
        let rules = order.map(|i| variants[i]);
        let mut g = guard(&rules);
        let verdict = g.authorize(tool("a", "op", b"{}"), 1, None, &mut NoAudit);
        assert_eq!(
            verdict,
            Verdict {
                decision: Decision::Deny,
                reason: Reason::ExplicitDeny,
                rule_id: Some(3)
            }
        );
        assert_eq!(g.calls(), 0);
        assert_eq!(
            g.approve(tool("a", "op", b"{}"), 10).unwrap_err().reason,
            Reason::ExplicitDeny
        );
    }
}

#[test]
fn approval_wins_over_allow_and_smallest_rule_id_is_stable() {
    let rules = [
        Rule::new(4, ActionKind::Tool, "op", Decision::RequireApproval),
        Rule::new(5, ActionKind::Tool, "op", Decision::Allow),
        Rule::new(2, ActionKind::Tool, "op", Decision::RequireApproval),
    ];
    let reversed = [rules[2], rules[1], rules[0]];
    for rules in [&rules[..], &reversed[..]] {
        let mut g = guard(rules);
        let v = g.authorize(tool("a", "op", b"{}"), 1, None, &mut NoAudit);
        assert_eq!(v.decision, Decision::RequireApproval);
        assert_eq!(v.rule_id, Some(2));
        assert_eq!(g.calls(), 0);
    }
}

#[test]
fn capabilities_combine_and_approval_cannot_override_them() {
    let rules = [
        ALLOW,
        Rule::new(9, ActionKind::Tool, "read", Decision::RequireApproval).requiring(4),
    ];
    let mut g = guard(&rules);
    let req = tool(
        "a",
        "read",
        br#"{"approved":true,"capabilities":65535,"readOnlyHint":true}"#,
    );
    assert_eq!(
        g.authorize(req, 1, None, &mut NoAudit).reason,
        Reason::MissingCapabilities
    );
    assert_eq!(
        g.approve(req, 20).unwrap_err().reason,
        Reason::MissingCapabilities
    );
}

#[test]
fn model_approval_fields_have_no_effect() {
    let mut g = guard(&[APPROVAL, DENY]);
    let arguments = br#"{"approved":true,"decision":"Allow","capabilities":18446744073709551615}"#;
    assert_eq!(
        g.authorize(tool("a", "write", arguments), 1, None, &mut NoAudit)
            .decision,
        Decision::RequireApproval
    );
    assert_eq!(
        g.authorize(tool("b", "delete", arguments), 2, None, &mut NoAudit)
            .reason,
        Reason::ExplicitDeny
    );
}

#[test]
fn exact_approval_allows_once_then_unapproved_retry_stops() {
    let mut g = guard(&[APPROVAL]);
    let req = tool("a", "write", br#"{"text":"hello"}"#);
    assert_eq!(
        g.authorize(req, 1, None, &mut NoAudit).decision,
        Decision::RequireApproval
    );
    let approval = g.approve(req, 10).unwrap();
    assert_eq!(
        g.authorize(req, 2, Some(approval), &mut NoAudit).reason,
        Reason::Approved
    );
    assert_eq!(
        g.authorize(req, 3, None, &mut NoAudit).decision,
        Decision::RequireApproval
    );
    assert_eq!(g.calls(), 1);
}

#[test]
fn approvals_bind_raw_bytes_ids_and_names_even_if_new_name_is_allowed() {
    let rules = [APPROVAL, ALLOW];
    let original = tool("a", "write", br#"{"v":1}"#);
    for request in [
        tool("a", "write", br#"{"v":2}"#),
        tool("a", "write", br#"{ "v":1 }"#),
        tool("b", "write", br#"{"v":1}"#),
        tool("a", "read", br#"{"v":1}"#),
    ] {
        let mut g = guard(&rules);
        let approval = g.approve(original, 10).unwrap();
        assert_eq!(
            g.authorize(request, 1, Some(approval), &mut NoAudit).reason,
            Reason::ApprovalMismatch
        );
        assert_eq!(g.calls(), 0);
    }
}

#[test]
fn approvals_bind_command_argument_boundaries_and_working_directory() {
    let rules = [Rule::new(
        1,
        ActionKind::Command,
        "/usr/bin/tool",
        Decision::RequireApproval,
    )];
    let original = Request::command("c", "/usr/bin/tool", &["ab", "c"], Some("/work"));
    for req in [
        Request::command("c", "/usr/bin/tool", &["a", "bc"], Some("/work")),
        Request::command("c", "/usr/bin/tool", &["ab", "c"], None),
        Request::command("c", "/usr/bin/tool", &["ab", "c"], Some("/work2")),
        Request::command("d", "/usr/bin/tool", &["ab", "c"], Some("/work")),
    ] {
        let mut g = guard(&rules);
        let approval = g.approve(original, 10).unwrap();
        assert_eq!(
            g.authorize(req, 1, Some(approval), &mut NoAudit).reason,
            Reason::ApprovalMismatch
        );
    }
    let mut g = guard(&rules);
    let approval = g.approve(original, 10).unwrap();
    assert!(
        g.authorize(original, 1, Some(approval), &mut NoAudit)
            .is_allowed()
    );
}

#[test]
fn approvals_bind_action_kind() {
    let rules = [
        Rule::new(1, ActionKind::Tool, "op", Decision::RequireApproval),
        Rule::new(2, ActionKind::Command, "op", Decision::RequireApproval),
    ];
    let mut g = guard(&rules);
    let approval = g.approve(tool("a", "op", b"{}"), 10).unwrap();
    assert_eq!(
        g.authorize(
            Request::command("a", "op", &["{}"], None),
            1,
            Some(approval),
            &mut NoAudit
        )
        .reason,
        Reason::ApprovalMismatch
    );
}

#[test]
fn approvals_bind_policy_rules_even_when_policy_id_is_reused() {
    let source = guard(&[APPROVAL]);
    let req = tool("a", "write", b"{}");
    let different = [APPROVAL, ALLOW];
    let mut destination = guard(&different);
    let approval = source.approve(req, 10).unwrap();
    assert_eq!(
        destination
            .authorize(req, 1, Some(approval), &mut NoAudit)
            .reason,
        Reason::ApprovalMismatch
    );
}

#[test]
fn approvals_bind_policy_revision_session_and_capabilities() {
    let rules = [APPROVAL];
    let source = guard(&rules);
    let req = tool("a", "write", b"{}");
    for (policy_id, context) in [
        (
            8,
            Context {
                session: 11,
                capabilities: 3,
            },
        ),
        (
            7,
            Context {
                session: 12,
                capabilities: 3,
            },
        ),
        (
            7,
            Context {
                session: 11,
                capabilities: 7,
            },
        ),
    ] {
        let mut destination = Guard::new(
            Policy::new(policy_id, &rules).unwrap(),
            context,
            Limits::default(),
        );
        let approval = source.approve(req, 10).unwrap();
        assert_eq!(
            destination
                .authorize(req, 1, Some(approval), &mut NoAudit)
                .reason,
            Reason::ApprovalMismatch
        );
    }
}

#[test]
fn equal_policy_and_context_describe_the_same_host_domain() {
    let rules = [APPROVAL];
    let source = guard(&rules);
    let mut destination = guard(&rules);
    let req = tool("a", "write", b"{}");
    let approval = source.approve(req, 10).unwrap();
    assert!(
        destination
            .authorize(req, 1, Some(approval), &mut NoAudit)
            .is_allowed()
    );
}

#[test]
fn expiry_is_exclusive_and_clock_regression_is_denied() {
    let rules = [APPROVAL, ALLOW];
    for now in [10, 11, u64::MAX] {
        let mut g = guard(&rules);
        let req = tool("a", "write", b"{}");
        let approval = g.approve(req, 10).unwrap();
        assert_eq!(
            g.authorize(req, now, Some(approval), &mut NoAudit).reason,
            Reason::ApprovalExpired
        );
    }
    let mut g = guard(&rules);
    let req = tool("a", "read", b"{}");
    assert!(g.authorize(req, 100, None, &mut NoAudit).is_allowed());
    assert_eq!(
        g.authorize(req, 99, None, &mut NoAudit).reason,
        Reason::ClockRegressed
    );
    assert!(g.authorize(req, 100, None, &mut NoAudit).is_allowed());
    assert_eq!(
        g.approve(tool("b", "write", b"{}"), 100)
            .unwrap_err()
            .reason,
        Reason::InvalidExpiry
    );
}

#[test]
fn payload_and_call_limits_accept_boundary_and_reject_next_byte_or_call() {
    let mut g = Guard::new(
        Policy::new(7, &[ALLOW]).unwrap(),
        Context {
            session: 1,
            capabilities: 0,
        },
        Limits {
            max_calls: 1,
            max_payload_bytes: 2,
        },
    );
    let req = tool("a", "read", b"{}");
    assert_eq!(
        g.authorize(tool("b", "read", b"{} "), 1, None, &mut NoAudit)
            .reason,
        Reason::PayloadLimit
    );
    assert_eq!(g.calls(), 0);
    assert!(g.authorize(req, 2, None, &mut NoAudit).is_allowed());
    assert_eq!(g.remaining_calls(), 0);
    assert_eq!(
        g.authorize(req, 3, None, &mut NoAudit).reason,
        Reason::CallLimit
    );
}

#[test]
fn zero_quota_denies_and_zero_byte_budget_accepts_empty_payload() {
    let mut g = Guard::new(
        Policy::new(7, &[ALLOW]).unwrap(),
        Context {
            session: 1,
            capabilities: 0,
        },
        Limits {
            max_calls: 0,
            max_payload_bytes: 0,
        },
    );
    assert_eq!(
        g.authorize(tool("a", "read", b""), 1, None, &mut NoAudit)
            .reason,
        Reason::CallLimit
    );
    let mut g = Guard::new(
        Policy::new(7, &[ALLOW]).unwrap(),
        Context {
            session: 1,
            capabilities: 0,
        },
        Limits {
            max_calls: 1,
            max_payload_bytes: 0,
        },
    );
    assert!(
        g.authorize(tool("a", "read", b""), 1, None, &mut NoAudit)
            .is_allowed()
    );
}

#[test]
fn pending_approval_cannot_bypass_new_quota_or_input_limits() {
    let rules = [APPROVAL];
    let source = guard(&rules);
    let req = tool("a", "write", b"{}");
    for (limits, expected) in [
        (
            Limits {
                max_calls: 0,
                max_payload_bytes: 100,
            },
            Reason::CallLimit,
        ),
        (
            Limits {
                max_calls: 10,
                max_payload_bytes: 1,
            },
            Reason::PayloadLimit,
        ),
    ] {
        let mut destination = Guard::new(source.policy(), source.context(), limits);
        let approval = source.approve(req, 10).unwrap();
        assert_eq!(
            destination
                .authorize(req, 1, Some(approval), &mut NoAudit)
                .reason,
            expected
        );
    }
}

#[test]
fn command_byte_budget_counts_cwd_and_utf8_without_joining_argv() {
    let req = Request::command("a", "/bin/tool", &["é", "x"], Some("/w"));
    assert_eq!(req.payload_bytes(), Some(5));
    let rules = [Rule::new(
        1,
        ActionKind::Command,
        "/bin/tool",
        Decision::Allow,
    )];
    let mut g = Guard::new(
        Policy::new(7, &rules).unwrap(),
        Context {
            session: 1,
            capabilities: 0,
        },
        Limits {
            max_calls: 1,
            max_payload_bytes: 4,
        },
    );
    assert_eq!(
        g.authorize(req, 1, None, &mut NoAudit).reason,
        Reason::PayloadLimit
    );
}

#[test]
fn audit_failure_prevents_calls_and_sequences_never_repeat() {
    let mut g = guard(&[ALLOW]);
    let req = tool("a", "read", b"{}");
    assert_eq!(
        g.authorize(req, 1, None, &mut Unavailable).reason,
        Reason::AuditFailed
    );
    assert_eq!(g.calls(), 0);
    let mut log = Log::default();
    assert!(g.authorize(req, 2, None, &mut log).is_allowed());
    assert_eq!(log.0[0].sequence, 2);
    assert_eq!(g.calls(), 1);
}

#[test]
fn audit_failure_consumes_approval_and_unapproved_retry_does_not_execute() {
    let mut g = guard(&[APPROVAL]);
    let req = tool("a", "write", b"{}");
    let approval = g.approve(req, 10).unwrap();
    assert_eq!(
        g.authorize(req, 1, Some(approval), &mut Unavailable).reason,
        Reason::AuditFailed
    );
    assert_eq!(
        g.authorize(req, 2, None, &mut NoAudit).decision,
        Decision::RequireApproval
    );
    assert_eq!(g.calls(), 0);
}

#[test]
fn audit_and_debug_do_not_expose_request_content() {
    let mut g = guard(&[APPROVAL]);
    let req = tool(
        "private-call-id",
        "write",
        br#"{"token":"very-private-value"}"#,
    );
    let approval = g.approve(req, 10).unwrap();
    let approval_debug = format!("{approval:?}");
    let request_debug = format!("{req:?}");
    let mut log = Log::default();
    assert!(g.authorize(req, 1, Some(approval), &mut log).is_allowed());
    let debug = format!("{:?}", log.0);
    for rendered in [debug, approval_debug, request_debug] {
        for private in ["private-call-id", "very-private-value", "token", "write"] {
            assert!(!rendered.contains(private), "{rendered}");
        }
    }
}

#[test]
fn invalid_descriptors_fail_before_permission() {
    let mut g = guard(&[ALLOW]);
    for req in [
        tool("", "read", b"{}"),
        tool("a\0b", "read", b"{}"),
        tool("a", "read\0", b"{}"),
    ] {
        assert_eq!(
            g.authorize(req, 1, None, &mut NoAudit).reason,
            Reason::InvalidRequest
        );
    }
    let rules = [Rule::new(1, ActionKind::Command, "cmd", Decision::Allow)];
    let mut g = guard(&rules);
    for req in [
        Request::command("a", "cmd", &["\0"], None),
        Request::command("a", "cmd", &[], Some("")),
    ] {
        assert_eq!(
            g.authorize(req, 1, None, &mut NoAudit).reason,
            Reason::InvalidRequest
        );
    }
}

#[test]
fn policy_rejects_duplicate_ids_and_invalid_names() {
    assert_eq!(
        Policy::new(1, &[ALLOW, ALLOW]).unwrap_err(),
        PolicyError::DuplicateRuleId { rule_id: 1 }
    );
    for name in ["", "has space", "line\nbreak", "nonasciié"] {
        assert_eq!(
            Policy::new(1, &[Rule::new(4, ActionKind::Tool, name, Decision::Allow)]).unwrap_err(),
            PolicyError::InvalidName { rule_id: 4 }
        );
    }
}

#[test]
fn pure_evaluation_does_not_reserve_and_denied_execution_has_zero_effects() {
    let mut g = guard(&[ALLOW, APPROVAL, DENY]);
    let mut effects = 0;
    for _ in 0..20 {
        assert!(g.evaluate(tool("a", "read", b"{}")).is_allowed());
    }
    assert_eq!(g.calls(), 0);
    for name in ["write", "delete", "missing"] {
        if g.authorize(tool("a", name, b"{}"), 1, None, &mut NoAudit)
            .is_allowed()
        {
            effects += 1;
        }
    }
    assert_eq!(effects, 0);
    if g.authorize(tool("a", "read", b"{}"), 2, None, &mut NoAudit)
        .is_allowed()
    {
        effects += 1;
    }
    assert_eq!(effects, 1);
}
