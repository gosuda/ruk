use super::*;
use ruk_core::protocol::{MAX_PAGE_SIZE, PushReconcileCursor, ReportedReconcileObservation};
use serde::{Deserialize, Serialize};

const VERSION: u8 = 1;
const PROGRESS_PREFIX: &[u8] = b"push-reconcile-progress\0";
const PAGE_PREFIX: &[u8] = b"push-reconcile-page\0";
const MAX_PAGES: u32 = 1024;
const MAX_PAGE_PAYLOAD: usize = ruk_core::MAX_CONTROL_FRAME_BYTES / 2;

pub(super) struct PreparedPage {
    pub reply: Reply,
    pub facts: Vec<FactMutation>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Progress {
    version: u8,
    principal: Principal,
    session: SessionId,
    request: RequestId,
    plan_hash: Oid,
    total: u64,
    reported_total: u64,
    page_count: u32,
    next_page: u32,
}

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PageRows {
    observations: Vec<ReconcileObservation>,
    reported_observations: Vec<ReportedReconcileObservation>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredPage {
    version: u8,
    session: SessionId,
    request: RequestId,
    index: u32,
    rows: PageRows,
}

enum Row {
    Observation(ReconcileObservation),
    Reported(ReportedReconcileObservation),
}

fn key(prefix: &[u8], plan: PlanId, page: Option<u32>) -> Vec<u8> {
    let mut key = Vec::with_capacity(prefix.len() + 20);
    key.extend_from_slice(prefix);
    key.extend_from_slice(plan.as_bytes());
    if let Some(page) = page {
        key.extend_from_slice(&page.to_be_bytes());
    }
    key
}

fn stale(message: &str) -> CoreError {
    CoreError::new(ErrorCode::EStale, message)
}

fn corrupt(message: &str) -> CoreError {
    CoreError::new(ErrorCode::ECorrupt, message)
}

fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, CoreError> {
    let bytes = sonic_rs::to_vec(value).map_err(|err| {
        CoreError::new(ErrorCode::EInvalid, format!("reconciliation snapshot encode: {err}"))
    })?;
    if bytes.len() > ruk_core::MAX_CONTROL_FRAME_BYTES {
        return Err(CoreError::new(
            ErrorCode::ELimit,
            "reconciliation snapshot row exceeds the control bound",
        ));
    }
    Ok(bytes)
}

fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, CoreError> {
    if bytes.len() > ruk_core::MAX_CONTROL_FRAME_BYTES {
        return Err(corrupt("reconciliation snapshot row exceeds the control bound"));
    }
    sonic_rs::from_slice(bytes).map_err(|err| {
        corrupt(&format!("reconciliation snapshot decode: {err}"))
    })
}

fn plan_hash(plan: &PushPlanRecord, kind: HashKind) -> Result<Oid, CoreError> {
    let encoded = plan.encode(kind).map_err(to_core)?;
    Ok(HashKind::Sha256.hash_parts(&[b"ruk-reconciliation-plan-v1\0", &encoded])?)
}

fn progress(store: &Store, plan: PlanId) -> Result<Option<(Progress, Vec<u8>)>, CoreError> {
    let Some(bytes) = store.fact(FactTable::RemoteObservations, &key(PROGRESS_PREFIX, plan, None))?
    else {
        return Ok(None);
    };
    let value: Progress = decode(&bytes)?;
    if value.version != VERSION
        || value.page_count == 0
        || value.page_count > MAX_PAGES
        || value.next_page == 0
        || value.next_page > value.page_count
    {
        return Err(corrupt("reconciliation snapshot progress is invalid"));
    }
    Ok(Some((value, bytes)))
}

fn mutation(
    store: &Store,
    key: Vec<u8>,
    value: Option<Vec<u8>>,
) -> Result<FactMutation, CoreError> {
    let previous = store.fact(FactTable::RemoteObservations, &key)?;
    Ok(FactMutation {
        table: FactTable::RemoteObservations,
        key,
        expected: previous.map_or(FactExpectation::Absent, FactExpectation::Value),
        value,
    })
}

fn split_rows(
    observations: Vec<ReconcileObservation>,
    reported: Vec<ReportedReconcileObservation>,
) -> Result<Vec<PageRows>, CoreError> {
    let mut pages = Vec::new();
    let mut page = PageRows::default();
    let mut count = 0;
    let mut bytes = 0;
    let rows = observations
        .into_iter()
        .map(Row::Observation)
        .chain(reported.into_iter().map(Row::Reported));
    for row in rows {
        let size = match &row {
            Row::Observation(value) => sonic_rs::to_vec(value),
            Row::Reported(value) => sonic_rs::to_vec(value),
        }
        .map_err(|err| {
            CoreError::new(ErrorCode::EInvalid, format!("reconciliation row encode: {err}"))
        })?
        .len()
            + 1;
        if size > MAX_PAGE_PAYLOAD {
            return Err(CoreError::new(
                ErrorCode::ELimit,
                "one reconciliation observation exceeds the page byte bound",
            ));
        }
        if count == MAX_PAGE_SIZE || bytes + size > MAX_PAGE_PAYLOAD {
            pages.push(page);
            if pages.len() >= usize::try_from(MAX_PAGES).expect("page bound fits usize") {
                return Err(CoreError::new(
                    ErrorCode::ELimit,
                    "reconciliation exceeds the snapshot page bound",
                ));
            }
            page = PageRows::default();
            count = 0;
            bytes = 0;
        }
        match row {
            Row::Observation(value) => page.observations.push(value),
            Row::Reported(value) => page.reported_observations.push(value),
        }
        count += 1;
        bytes += size;
    }
    pages.push(page);
    Ok(pages)
}

fn reply(
    plan: &PushPlanRecord,
    page: PageRows,
    progress: &Progress,
    session: SessionId,
    request: RequestId,
) -> Result<Reply, CoreError> {
    let next = (progress.next_page < progress.page_count).then_some(PushReconcileCursor {
        session: progress.session,
        request: progress.request,
        page: progress.next_page,
    });
    Ok(Reply::PushReconcile(Box::new(PushReconcileReply {
        outcome: pending_outcome(session, request),
        plan: plan.id,
        state: wire_state(plan.state),
        rewritten: !plan.reported_updates.is_empty(),
        observations: BoundedList::excerpt(page.observations, progress.total)?,
        reported_observations: BoundedList::excerpt(
            page.reported_observations,
            progress.reported_total,
        )?,
        next,
    })))
}

pub(super) fn first(
    job: &PushJob<'_>,
    plan: &PushPlanRecord,
    observations: Vec<ReconcileObservation>,
    reported: Vec<ReportedReconcileObservation>,
    request: RequestId,
    clear_legacy_marker: bool,
) -> Result<PreparedPage, CoreError> {
    let store = job.coordinator.store();
    let session = job.session;
    let total = u64::try_from(observations.len()).expect("row count fits u64");
    let reported_total = u64::try_from(reported.len()).expect("row count fits u64");
    let pages = split_rows(observations, reported)?;
    let page_count = u32::try_from(pages.len()).expect("page count is bounded");
    let previous = progress(store, plan.id)?;
    let value = Progress {
        version: VERSION,
        principal: job.principal.clone(),
        session,
        request,
        plan_hash: plan_hash(plan, store.hash_kind())?,
        total,
        reported_total,
        page_count,
        next_page: 1,
    };
    let mut facts = Vec::with_capacity(pages.len() + 2);
    let mut first = None;
    for (index, rows) in pages.into_iter().enumerate() {
        let index = u32::try_from(index).expect("page count is bounded");
        let stored = StoredPage {
            version: VERSION,
            session,
            request,
            index,
            rows,
        };
        facts.push(mutation(
            store,
            key(PAGE_PREFIX, plan.id, Some(index)),
            Some(encode(&stored)?),
        )?);
        if index == 0 {
            first = Some(stored.rows);
        }
    }
    if let Some((old, _)) = &previous {
        for index in page_count..old.page_count {
            facts.push(mutation(store, key(PAGE_PREFIX, plan.id, Some(index)), None)?);
        }
    }
    facts.push(FactMutation {
        table: FactTable::RemoteObservations,
        key: key(PROGRESS_PREFIX, plan.id, None),
        expected: previous.map_or(FactExpectation::Absent, |(_, bytes)| {
            FactExpectation::Value(bytes)
        }),
        value: Some(encode(&value)?),
    });
    let complete = page_count == 1;
    if complete || clear_legacy_marker {
        let mut marker = reconciliation_marker_fact(store, plan.id)?;
        if !complete {
            marker.value = None;
        }
        facts.push(marker);
    }
    Ok(PreparedPage {
        reply: reply(plan, first.expect("snapshot has a first page"), &value, session, request)?,
        facts,
    })
}

pub(super) fn next(
    job: &PushJob<'_>,
    plan: &PushPlanRecord,
    cursor: PushReconcileCursor,
    request: RequestId,
) -> Result<PreparedPage, CoreError> {
    let store = job.coordinator.store();
    let session = job.session;
    let Some((mut value, previous)) = progress(store, plan.id)? else {
        return Err(stale("reconciliation snapshot is no longer available; start again"));
    };
    if value.principal != *job.principal {
        return Err(CoreError::new(
            ErrorCode::EForbidden,
            "reconciliation snapshot belongs to another principal",
        ));
    }
    if cursor.session != value.session
        || cursor.request != value.request
        || cursor.page != value.next_page
        || value.next_page >= value.page_count
        || plan_hash(plan, store.hash_kind())? != value.plan_hash
    {
        return Err(stale("reconciliation cursor or plan changed; start again"));
    }
    let page_key = key(PAGE_PREFIX, plan.id, Some(cursor.page));
    let bytes = store
        .fact(FactTable::RemoteObservations, &page_key)?
        .ok_or_else(|| corrupt("reconciliation snapshot page is missing"))?;
    let stored: StoredPage = decode(&bytes)?;
    if stored.version != VERSION
        || stored.session != cursor.session
        || stored.request != cursor.request
        || stored.index != cursor.page
        || stored.rows.observations.len() + stored.rows.reported_observations.len() > MAX_PAGE_SIZE
    {
        return Err(corrupt("reconciliation snapshot page is invalid"));
    }
    value.next_page += 1;
    let complete = value.next_page == value.page_count;
    let mut facts = vec![FactMutation {
        table: FactTable::RemoteObservations,
        key: key(PROGRESS_PREFIX, plan.id, None),
        expected: FactExpectation::Value(previous),
        value: Some(encode(&value)?),
    }];
    if complete {
        facts.push(reconciliation_marker_fact(store, plan.id)?);
    }
    Ok(PreparedPage {
        reply: reply(plan, stored.rows, &value, session, request)?,
        facts,
    })
}

pub(super) fn can_release_receipt(
    store: &Store,
    plan: &PushPlanRecord,
    reply: &Reply,
) -> Result<bool, CoreError> {
    let Reply::PushReconcile(reply) = reply else {
        return Err(corrupt("reconciliation receipt names another method"));
    };
    if !plan.destination_is_known() || reply.next.is_some() {
        return Ok(false);
    }
    match store.fact(FactTable::RemoteObservations, &reconciliation_marker_key(plan.id))? {
        Some(value) if value == [RECONCILIATION_MARKER_VERSION] => Ok(true),
        Some(_) => Err(corrupt("reconciliation marker is corrupt")),
        None => Ok(false),
    }
}
