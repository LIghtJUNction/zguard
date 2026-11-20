use zguard::*;

struct ConsoleAudit;
impl Audit for ConsoleAudit {
    fn record(&mut self, event: AuditEvent) -> Result<(), AuditFailure> {
        println!(
            "policy={} sequence={} decision={:?} reason={:?}",
            event.policy_id, event.sequence, event.verdict.decision, event.verdict.reason
        );
        Ok(())
    }
}
fn main() -> Result<(), PolicyError> {
    let rules = [
        Rule::new(1, ActionKind::Tool, "notes.read", Decision::Allow).requiring(1),
        Rule::new(
            2,
            ActionKind::Tool,
            "notes.write",
            Decision::RequireApproval,
        )
        .requiring(2),
        Rule::new(3, ActionKind::Tool, "system.shell", Decision::Deny),
    ];
    let mut guard = Guard::new(
        Policy::new(1, &rules)?,
        Context {
            session: 1,
            capabilities: 3,
        },
        Limits {
            max_calls: 2,
            max_payload_bytes: 1024,
        },
    );
    let mut audit = ConsoleAudit;
    let read = Request::tool("read-1", "notes.read", br#"{"note":"example"}"#);
    let mut executed = 0;
    if guard.authorize(read, 1, None, &mut audit).is_allowed() {
        executed += 1;
    }
    let write = Request::tool("write-1", "notes.write", br#"{"text":"hello"}"#);
    assert_eq!(
        guard.authorize(write, 2, None, &mut audit).decision,
        Decision::RequireApproval
    );
    // The trusted application has obtained external approval for this exact call.
    let approval = guard
        .approve(write, 10)
        .expect("host-approved bounded request");
    if guard
        .authorize(write, 3, Some(approval), &mut audit)
        .is_allowed()
    {
        executed += 1;
    }
    assert_eq!(executed, 2);
    assert_eq!(guard.remaining_calls(), 0);
    println!("authorized example operations: {executed}");
    Ok(())
}
