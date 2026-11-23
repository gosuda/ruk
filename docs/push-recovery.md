# Recover an uncertain push

A lost push response does not prove that the remote rejected the update.
Ruk retains the push plan and blocks another hosted push to the affected
destination and refs. Use `push.reconcile` to observe the remote before
you decide whether to send again.

For a plan with a recorded destination, send the plan identifier in the
method's arguments:

```json
{"plan":"00000000-0000-4000-8000-000000000001"}
```

Replace the example identifier with the plan from the `E_PUSH_UNCERTAIN`
error. Use the normal authenticated request envelope, session, and request
identifier. A successful reconciliation records the observation and
releases that plan's guard. It does not send a push. Check the returned
ref names, observed OIDs, and verdicts before you create another push.

## Plans from older versions

Some older plans contain a remote name such as `origin` instead of its
resolved URL. Other older plans lost an explicit SSH username. These
records cannot identify the original destination. Ruk conservatively
blocks their affected refs across destinations.

Recover the destination from the original operation's trusted records.
Do not assume that the current remote configuration has the same value.
Supply that original resolved destination in `original_remote`:

```json
{
  "plan":"00000000-0000-4000-8000-000000000001",
  "original_remote":"ssh://alice@mirror.example:2222/repo.git"
}
```

The caller must verify that this is the destination used by the original
push. Ruk cannot recover information that the old record omitted. The
server applies its normal authentication and destination policies. It
observes the destination, then commits the bound plan and reconciliation
record together. Only then does it release that plan's legacy guard.
Other unresolved plans keep their guards.

`original_remote` is accepted only when the saved destination is unknown.
It cannot change the destination of a plan that already identifies one.
An old reconciliation record alone cannot recover a missing destination.
For an older local push, supply the absolute path of the destination
repository or its store. Local push plans reside in that destination
store. The path must identify the same hosted store that contains the
plan. Ruk applies its path containment checks and reads that already
authorized store. Recovery cannot open another local repository.

## Server-reported changes

A receive hook can report a different ref or OID from the requested
update. Ruk retains validated reported destinations separately from the
request and leaves the push uncertain. Reconciliation observes both the
requested and reported refs. A reply with `rewritten: true` requires a
decision about the reported result before another send. Reconciliation
does not turn that result into confirmation of the original request.
