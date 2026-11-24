"use client";

import { useEffect, useState } from "react";
import { apiGet } from "@/lib/api";
import { useSession } from "@/components/session-provider";

type Summary = {
  window_days: number;
  sampled: boolean;
  metrics: Record<string, number | null | Record<string, number>>;
  limitations: string[];
  recent_action_traces?: Array<Record<string, string | null>>;
};

export function ObservabilityDashboard() {
  const { session } = useSession();
  const [data, setData] = useState<Summary | null>(null);
  const [error, setError] = useState("");
  useEffect(() => {
    let active = true;
    apiGet<Summary>("/api/v1/observability/summary", session, { cacheMs: 15000 })
      .then(value => { if (active) setData(value); })
      .catch(reason => { if (active) setError(reason instanceof Error ? reason.message : "Metrics unavailable"); });
    return () => { active = false; };
  }, [session]);

  const metrics = data?.metrics ?? {};
  const labels: Record<string, string> = {
    query_count: "Recorded agent queries",
    precision: "Claim support precision (latest eval)",
    refusal_ratio: "Refusal ratio",
    tools_per_question: "Tools per question",
    graph_loop_iterations: "Planner iterations",
    policy_denials: "Policy denials",
    approval_count: "Approvals",
    execution_count: "Sandbox executions",
    execution_idempotent_replays: "Idempotent execution retries",
    latest_observation_age_hours: "Latest observation age (hours)",
    test_pass_rate: "Security test pass rate",
  };
  return <>
    <header className="page-title"><span className="eyebrow">SAMPLED · TENANT SCOPED</span><h1>Observability</h1><p>Seven day graph, policy and action metrics. Ratios remain unavailable when no denominator exists.</p></header>
    {error && <p role="alert" className="notice danger">{error}</p>}
    {!data && !error && <p className="muted">Loading tenant metrics…</p>}
    {data && <>
      <section className="metric-grid">{Object.entries(labels).map(([key, label]) => {
        const value = metrics[key];
        return <article className="metric-card" key={key}><span>{label}</span><strong>{value === null || value === undefined ? "Unavailable" : typeof value === "number" ? Number.isInteger(value) ? value : value.toFixed(3) : "—"}</strong></article>;
      })}</section>
      <section className="panel"><h2>Tool counts</h2><dl className="details">{Object.entries((metrics.tool_counts ?? {}) as Record<string, number>).map(([name, count]) => <div key={name}><dt>{name}</dt><dd>{count}</dd></div>)}{!Object.keys((metrics.tool_counts ?? {}) as object).length && <p className="muted">No tool calls in the reporting window.</p>}</dl></section>
      <section className="panel"><h2>Recent action audit traces</h2><div className="timeline">{(data.recent_action_traces ?? []).map((event, index) => <div className="timeline-row" key={`${event.trace_id}-${index}`}><span className="timeline-mark">{String(index + 1).padStart(2, "0")}</span><span><strong>{event.event_type} · proposal {event.proposal_id}</strong><small>Trace {event.trace_id ?? "not recorded"}{event.simulation_label ? ` · ${event.simulation_label}` : ""}{event.execution_id ? ` · execution ${event.execution_id}` : ""}</small></span><span className="pill neutral">Audit</span></div>)}{!(data.recent_action_traces ?? []).length && <p className="muted">No approval or execution audit events in the reporting window.</p>}</div><p className="footnote">Sandbox records are explicitly labeled; approval alone does not imply execution.</p></section>
      <p className="footnote">Sample capped at 10,000 events per tenant. Metrics are aggregated from sanitized step and audit events; prompts, telemetry text, and employee identifiers are not shown.</p>
    </>}
  </>;
}
