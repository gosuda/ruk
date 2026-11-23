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
identifier. A completed reconciliation records the observation and
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
A retry with the same session and request identifier replays its stored
observation. That replay keeps the legacy guard until a separate request
verifies and commits the original destination.

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


## Large recovery results

A response contains at most 1,000 observations across `observations` and
`reported_observations`. Large results include a `next` cursor. Pass it
as `cursor` with the same plan and a new request identifier:

```json
{
  "plan":"00000000-0000-4000-8000-000000000001",
  "cursor":{
    "session":"00000000-0000-4000-8000-000000000002",
    "request":"00000000-0000-4000-8000-000000000003",
    "page":1
  }
}
```

Use the cursor returned by Ruk, not these example values. Omit
`original_remote` and `original_ssh` from continuation requests.
Each page comes from the same saved observation snapshot. A restart does
not require another network observation. An outstanding guard remains until the last
page commits and `next` is null. Retrying an earlier page's request
identifier replays that page and does not complete the recovery.

The totals in each list describe the entire snapshot, not just that
page. Collect both lists until `next` is null. If the plan or snapshot
changes, Ruk returns `E_STALE`; start a new reconciliation without a
cursor. Starting again replaces the previous snapshot and invalidates
its unfinished cursors.

`observations` preserves the comparisons against the requested pins.
`reported_observations` exposes each reported alternative's old and new
OIDs, observed value, and separate verdict. A same-ref OID rewrite can
therefore be `moved` relative to the request and `equal_new` relative to
the reported result. It still requires a decision before another send.
