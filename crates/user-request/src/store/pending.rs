// SPDX-License-Identifier: MIT OR Apache-2.0
//! Durable pending requests (user-request #4): a request that outlives the
//! process, the reboot and the day, and has NO timeout of its own.
//!
//! What the person sees is unchanged (CireSnave, 2026-10-07, board 134): the
//! Windows Hello prompt alone, showing who asks, which secret and for how
//! long. A pending request is only a record that someone asked; it holds no
//! privilege. Answering it is a NEW prompt through the gate, so a restored
//! request re-prompts and never approves by itself.
//!
//! `bound_hash` binds the request to the artifact the consumer will act on
//! (agentlife: the frozen plan hash). The consumer states the hash it holds
//! now when it answers; any difference voids the request, fail closed.
//! `seal` binds every field of the record to every other, under the store's
//! key, so an altered record is caught at the answer.
//!
//! The records live in `grants.json`, beside the grants, so an approval
//! makes its grant and spends its request in ONE write: a crash cannot leave
//! a grant with its request still open to a second approval.

use super::*;
use crate::channel::MAX_ROLE_CHARS;

/// Most pending requests one role may hold. A request never expires on its
/// own, so the count is what stops a lane filling the file.
pub const MAX_PENDING_PER_ROLE: usize = 20;
/// Most pending requests the store holds.
pub const MAX_PENDING: usize = 100;
/// `bound_hash` is a hash, not a document.
const MAX_BOUND_HASH_CHARS: usize = 128;
/// A record never expires, so what it may hold is bounded too. The prompt clips
/// a subject at 200 characters; a longer one hides its tail from the person.
const MAX_SUBJECT_CHARS: usize = 200;
const MAX_TEXT_CHARS: usize = 1024;

/// One request nobody has answered yet.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PendingRequest {
    /// 128 random bits, hex.
    pub id: String,
    pub created_at: DateTime<Utc>,
    pub request: Request,
    /// What was asked for, as the requester stated it.
    pub grant: Grant,
    /// The artifact this request is bound to (the consumer's own hash).
    pub bound_hash: String,
    /// HMAC over every field above, under the store key.
    pub seal: String,
}

/// What `begin_answer` hands back: show `request` with `grant` through a
/// channel (with the store dropped, as for any prompt), then `resolve`.
#[derive(Clone, Debug, PartialEq)]
pub struct Asking {
    pub pending_id: String,
    pub request: Request,
    pub grant: Grant,
    pub bound_hash: String,
    pub reservation: Reservation,
}

/// The record's seal: every field, in a fixed order, under the store key.
fn seal_of(
    key: &[u8],
    id: &str,
    created_at: DateTime<Utc>,
    request: &Request,
    grant: &Grant,
    bound_hash: &str,
) -> String {
    let bytes = serde_json::to_vec(&(
        "pending-request",
        id,
        created_at,
        request,
        grant,
        bound_hash,
    ))
    .expect("plain data serialises");
    mac(key, &bytes)
}

/// A hash, short and plain: it goes into the audit log.
fn check_bound_hash(h: &str) -> Result<(), String> {
    if h.is_empty() || h.chars().count() > MAX_BOUND_HASH_CHARS || h.chars().any(char::is_control) {
        return Err(format!(
            "bound_hash must be 1 to {MAX_BOUND_HASH_CHARS} plain characters"
        ));
    }
    Ok(())
}

/// Is the end an approval carries the one this request asked for? A relative
/// length runs from the moment the prompt was shown, which lies between the
/// reservation and the approval.
pub(super) fn is_what_was_requested(
    asked: &Grant,
    ap: &Approval,
    reserved_at: DateTime<Utc>,
) -> bool {
    match (asked, ap.expires_at) {
        (Grant::Forever, None) => true,
        (Grant::Until(t), Some(e)) => e == *t,
        (Grant::For { secs }, Some(e)) => Duration::try_seconds(*secs)
            .and_then(|d| e.checked_sub_signed(d))
            .is_some_and(|shown| shown >= reserved_at && shown <= ap.approved_at),
        _ => false,
    }
}

impl Store {
    /// Requests nobody has answered yet.
    pub fn pending(&self) -> &[PendingRequest] {
        &self.pending
    }

    /// Records a request that outlives this process, and returns its id.
    /// Refused, before anything is stored or shown, for a grant over the
    /// kind's maximum (never clamped), a store that cannot be trusted, and a
    /// role or store that already holds its share. The same request again
    /// returns the id it already has.
    pub fn submit(
        &mut self,
        req: &Request,
        grant: &Grant,
        bound_hash: &str,
    ) -> Result<String, String> {
        self.submit_at(req, grant, bound_hash, Utc::now())
    }

    pub(crate) fn submit_at(
        &mut self,
        req: &Request,
        grant: &Grant,
        bound_hash: &str,
        now: DateTime<Utc>,
    ) -> Result<String, String> {
        self.writable()?;
        self.trustworthy()?;
        check_bound_hash(bound_hash)?;
        req.check_subject()?;
        let role = req.requester.role.as_str();
        if role.chars().count() > MAX_ROLE_CHARS {
            return Err(format!(
                "requester role is longer than {MAX_ROLE_CHARS} characters"
            ));
        }
        for (what, text, max) in [
            ("subject", &req.subject, MAX_SUBJECT_CHARS),
            ("summary", &req.summary, MAX_TEXT_CHARS),
            ("reason", &req.reason, MAX_TEXT_CHARS),
        ] {
            if text.chars().count() > max {
                return Err(format!("the {what} is longer than {max} characters"));
            }
        }
        if !grant.within(req.kind.max(), now.with_timezone(&Local)) {
            return Err(format!(
                "{} is over the maximum for {:?}: refused, never clamped",
                grant.describe(now),
                req.kind
            ));
        }
        if let Some(p) = self
            .pending
            .iter()
            .find(|p| p.request == *req && p.grant == *grant && p.bound_hash == bound_hash)
        {
            return Ok(p.id.clone());
        }
        let mine = self
            .pending
            .iter()
            .filter(|p| p.request.requester.role == role)
            .count();
        if mine >= MAX_PENDING_PER_ROLE {
            return Err(format!(
                "'{role}' already has {mine} pending requests (cap {MAX_PENDING_PER_ROLE})"
            ));
        }
        if self.pending.len() >= MAX_PENDING {
            return Err(format!(
                "the store already holds {} pending requests (cap {MAX_PENDING})",
                self.pending.len()
            ));
        }
        let id = random_id();
        self.pending.push(PendingRequest {
            seal: seal_of(&self.key, &id, now, req, grant, bound_hash),
            id: id.clone(),
            created_at: now,
            request: req.clone(),
            grant: grant.clone(),
            bound_hash: bound_hash.to_string(),
        });
        let recorded = self
            .audit(
                now,
                "pending-submitted",
                &format!(
                    "pending={id} role={role} kind={:?} subject={} bound_hash={bound_hash}",
                    req.kind,
                    normal_subject(&req.subject)
                ),
            )
            .and_then(|()| self.save(now));
        if let Err(e) = recorded {
            // not recorded, so not kept
            self.pending.retain(|p| p.id != id);
            return Err(e);
        }
        Ok(id)
    }

    /// Starts answering pending request `id`, given the `bound_hash` the
    /// consumer holds NOW. The request is voided, and the person never asked,
    /// when its record was altered, the hash differs, or its grant has ended.
    /// Otherwise a prompt is reserved through the gate like any other, and the
    /// caller drops the store, shows `request` with `grant` through a
    /// channel, then `resolve`s. A restored request is a new prompt: nothing
    /// here approves anything. A request stays pending when the prompt is
    /// not answered; Cancel (a denial), a refusal and an approval end it.
    pub fn begin_answer(
        &mut self,
        id: &str,
        bound_hash: &str,
        alert: &dyn Alert,
    ) -> Result<Asking, String> {
        self.begin_answer_at(id, bound_hash, Utc::now(), alert)
    }

    pub(crate) fn begin_answer_at(
        &mut self,
        id: &str,
        bound_hash: &str,
        now: DateTime<Utc>,
        alert: &dyn Alert,
    ) -> Result<Asking, String> {
        self.writable()?;
        if let Err(why) = self.trustworthy() {
            alert.alert(&why);
            return Err(why);
        }
        let Some(p) = self.pending.iter().find(|p| p.id == id).cloned() else {
            return Err(format!(
                "no such pending request {id} (answered, withdrawn, voided or never made)"
            ));
        };
        let sealed = seal_of(
            &self.key,
            &p.id,
            p.created_at,
            &p.request,
            &p.grant,
            &p.bound_hash,
        );
        if sealed != p.seal {
            let why = format!("pending request {id} was altered after it was made; voided");
            alert.alert(&why);
            return Err(self.void(id, now, "pending-altered", &why));
        }
        if p.bound_hash != bound_hash {
            let why = format!(
                "pending request {id} is stale: its bound_hash is not the one now held; voided"
            );
            return Err(self.void(id, now, "pending-stale", &why));
        }
        if !p
            .grant
            .within(p.request.kind.max(), now.with_timezone(&Local))
        {
            let why = format!(
                "pending request {id} is stale: its grant has ended or is no longer within \
                 the maximum; voided"
            );
            return Err(self.void(id, now, "pending-stale", &why));
        }
        // one prompt at a time per request: two at once could each be approved
        if self.attempts.iter().any(|a| {
            a.pending.as_deref() == Some(id)
                && a.outcome == Ended::Pending
                && !self.ended.contains_key(&a.id)
                && now < a.at + RESERVATION_TTL
        }) {
            return Err(format!("pending request {id} is already being answered"));
        }
        let reservation = self.reserve(
            &p.request.requester,
            p.request.kind,
            &p.request.subject,
            now,
            alert,
            Some(p.id.clone()),
        )?;
        Ok(Asking {
            pending_id: p.id,
            request: p.request,
            grant: p.grant,
            bound_hash: p.bound_hash,
            reservation,
        })
    }

    /// The requester gives up on a pending request; a prompt for it that is
    /// already up can no longer be approved. `false` when there is none.
    pub fn withdraw(&mut self, id: &str) -> Result<bool, String> {
        self.withdraw_at(id, Utc::now())
    }

    pub(crate) fn withdraw_at(&mut self, id: &str, now: DateTime<Utc>) -> Result<bool, String> {
        self.writable()?;
        self.key_known()?;
        if !self.pending.iter().any(|p| p.id == id) {
            return Ok(false);
        }
        self.audit(now, "pending-withdrawn", &format!("pending={id}"))?;
        self.pending.retain(|p| p.id != id);
        for a in self
            .attempts
            .iter_mut()
            .filter(|a| a.pending.as_deref() == Some(id) && a.outcome == Ended::Pending)
        {
            a.outcome = Ended::NotAsked;
            self.ended.insert(a.id.clone(), a.at);
        }
        self.save(now)?;
        Ok(true)
    }

    /// Removes request `id`, audits `event` and saves; the message to hand
    /// back, with a note when the record could not be written.
    fn void(&mut self, id: &str, now: DateTime<Utc>, event: &str, why: &str) -> String {
        let recorded = self.audit(now, event, &format!("pending={id}"));
        self.pending.retain(|p| p.id != id);
        match recorded.and_then(|()| self.save(now)) {
            Ok(()) => why.to_string(),
            Err(e) => format!("{why} (and recording it failed: {e})"),
        }
    }
}

#[cfg(test)]
mod tests;
