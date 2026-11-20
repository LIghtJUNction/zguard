use std::{hint::black_box, time::Instant};
use zguard::*;

fn measure(label: &str, mut operation: impl FnMut()) {
    const N: u32 = 1_000_000;
    for _ in 0..10_000 {
        operation();
    }
    let begin = Instant::now();
    for _ in 0..N {
        operation();
    }
    let elapsed = begin.elapsed().as_nanos() as f64 / f64::from(N);
    println!("{label}: {elapsed:.2} ns/op ({N} iterations)");
}
fn main() {
    let rules = [
        Rule::new(1, ActionKind::Tool, "read", Decision::Allow).requiring(1),
        Rule::new(2, ActionKind::Tool, "write", Decision::RequireApproval).requiring(2),
        Rule::new(3, ActionKind::Tool, "shell", Decision::Deny),
    ];
    let policy = Policy::new(7, &rules).unwrap();
    let context = Context {
        session: 1,
        capabilities: 3,
    };
    let limits = Limits {
        max_calls: u64::MAX,
        max_payload_bytes: 4096,
    };
    let mut guard = Guard::new(policy, context, limits);
    let read = Request::tool("c1", "read", br#"{"path":"notes.txt"}"#);
    let write = Request::tool("c2", "write", br#"{"text":"example"}"#);
    measure("evaluate_allow_3_rules", || {
        let _ = black_box(guard.evaluate(black_box(read)));
    });
    measure("authorize_allow_no_audit_3_rules", || {
        let _ = black_box(guard.authorize(black_box(read), 1, None, &mut NoAudit));
    });
    measure("approve_and_authorize_3_rules", || {
        let approval = guard.approve(black_box(write), 10).unwrap();
        let _ = black_box(guard.authorize(black_box(write), 1, Some(approval), &mut NoAudit));
    });
    println!(
        "Guard={} bytes; Rule={} bytes; AuditEvent={} bytes; Approval={} bytes",
        core::mem::size_of::<Guard<'_>>(),
        core::mem::size_of::<Rule<'_>>(),
        core::mem::size_of::<AuditEvent>(),
        core::mem::size_of::<Approval<'_, '_>>()
    );
}
