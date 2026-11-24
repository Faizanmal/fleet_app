"use client";

import { useState } from "react";

type ProposalView = {
  proposal_id: number;
  proposal_hash: string;
  status: string;
  proposal: {
    tenant_key: string;
    actor_id: string;
    target_type: string;
    target_id: string;
    action_kind: string;
    payload: Record<string, unknown>;
    evidence_manifest_ids: string[];
    policy_facts: Record<string, unknown>;
    data_as_of: string;
    expires_at: string;
    mode: string;
    policy_version: string;
    graph_version: string;
  };
  approvals: Array<{ actor_id: string; actor_role: string; decision: string; decided_at: string }>;
  execution: { status: string; result: Record<string, unknown> } | null;
};

const baseUrl = process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000";

export default function ActionReview() {
  const [proposalId, setProposalId] = useState("");
  const [role, setRole] = useState<"operator" | "approver">("approver");
  const [proposal, setProposal] = useState<ProposalView | null>(null);
  const [confirmed, setConfirmed] = useState(false);
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);

  const headers = () => ({
    Authorization: `Bearer demo-acme-${role}`,
    "X-Active-Tenant": "acme-001",
    "Content-Type": "application/json",
  });

  async function loadProposal() {
    if (!/^\d+$/.test(proposalId)) {
      setMessage("Enter a numeric proposal ID.");
      return;
    }
    setBusy(true);
    setMessage("");
    try {
      const response = await fetch(`${baseUrl}/api/v1/actions/proposals/${proposalId}`, {
        headers: headers(),
        cache: "no-store",
      });
      const body = await response.json();
      if (!response.ok) throw new Error(body.error?.message ?? body.detail ?? "Proposal not found.");
      setProposal(body as ProposalView);
      setConfirmed(false);
    } catch (error) {
      setProposal(null);
      setMessage(error instanceof Error ? error.message : "Request failed.");
    } finally {
      setBusy(false);
    }
  }

  async function decide(decision: "approve" | "reject") {
    if (!proposal) return;
    if (decision === "approve" && !confirmed) return;
    setBusy(true);
    try {
      const response = await fetch(
        `${baseUrl}/api/v1/actions/proposals/${proposal.proposal_id}/decision`,
        {
          method: "POST",
          headers: headers(),
          body: JSON.stringify({ decision, proposal_hash: proposal.proposal_hash }),
        },
      );
      const body = await response.json();
      if (!response.ok) throw new Error(body.error?.message ?? (typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail)));
      setMessage(`Decision recorded: ${body.status}. Approval does not execute the operation.`);
      await loadProposal();
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Decision failed.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="action-review" aria-labelledby="action-review-title">
      <p className="eyebrow">HUMAN REVIEW</p>
      <h2 id="action-review-title">Action proposal review</h2>
      <p className="review-warning">
        Demo credentials work only when development fixture authentication is enabled. This browser flow does not execute actions.
      </p>
      <div className="proposal-load">
        <label htmlFor="proposal-id">Proposal ID</label>
        <input id="proposal-id" inputMode="numeric" value={proposalId} onChange={(event) => setProposalId(event.target.value)} />
        <label htmlFor="review-role">Act as</label>
        <select id="review-role" value={role} onChange={(event) => setRole(event.target.value as "operator" | "approver")}>
          <option value="approver">Approver</option>
          <option value="operator">Operator</option>
        </select>
        <button type="button" onClick={loadProposal} disabled={busy}>Load proposal</button>
      </div>
      {proposal && (
        <article className="proposal-card">
          <div className="proposal-heading">
            <div><span className="status-label">{proposal.status}</span><span className="mode-label">{proposal.proposal.mode}</span></div>
            <code>SHA-256 {proposal.proposal_hash}</code>
          </div>
          <dl className="proposal-facts">
            <div><dt>Exact operation</dt><dd>{proposal.proposal.action_kind}: {JSON.stringify(proposal.proposal.payload)}</dd></div>
            <div><dt>Target</dt><dd>{proposal.proposal.target_type} {proposal.proposal.target_id}</dd></div>
            <div><dt>Requested by</dt><dd>{proposal.proposal.actor_id}</dd></div>
            <div><dt>Tenant</dt><dd>{proposal.proposal.tenant_key}</dd></div>
            <div><dt>Evidence manifests</dt><dd>{proposal.proposal.evidence_manifest_ids.join(", ")}</dd></div>
            <div><dt>Evidence as of</dt><dd>{proposal.proposal.data_as_of}</dd></div>
            <div><dt>Expires</dt><dd>{proposal.proposal.expires_at}</dd></div>
            <div><dt>Policy facts</dt><dd><pre>{JSON.stringify(proposal.proposal.policy_facts, null, 2)}</pre></dd></div>
            <div><dt>Limitations</dt><dd>Historical data may be used only in clearly labeled simulation mode. Approval does not execute an operation. No external connector is enabled.</dd></div>
            <div><dt>Approvals</dt><dd>{proposal.approvals.length ? proposal.approvals.map((item) => `${item.decision} by ${item.actor_id} (${item.actor_role}) at ${item.decided_at}`).join("; ") : "No decision recorded"}</dd></div>
          </dl>
          {proposal.status === "PENDING_APPROVAL" && (
            <div className="decision-controls">
              <label className="confirm-check"><input type="checkbox" checked={confirmed} onChange={(event) => setConfirmed(event.target.checked)} /> I reviewed the exact operation, target, evidence, policy facts, and simulation mode.</label>
              <div className="button-row">
                <button type="button" className="approve-button" disabled={busy || role !== "approver" || !confirmed} onClick={() => decide("approve")}>Approve proposal</button>
                <button type="button" className="reject-button" disabled={busy || role !== "approver"} onClick={() => decide("reject")}>Reject proposal</button>
              </div>
            </div>
          )}
          {proposal.status === "APPROVED" && <p className="execution-result">Approved. Execution requires a separately authorized server workflow.</p>}
          {proposal.execution && <p className="execution-result">{proposal.execution.status}: {JSON.stringify(proposal.execution.result)}</p>}
        </article>
      )}
      {message && <p className="review-message" role="status">{message}</p>}
    </section>
  );
}
