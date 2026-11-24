export type Session = { tenant: string; role: "viewer" | "operator" | "approver" | "admin"; token: string };
export type Envelope<T = Record<string, unknown>> = {
  items?: T[]; total_count?: number; page?: number; page_size?: number;
  evidence_ids?: string[]; manifest_ids?: string[]; coverage?: Record<string, unknown>;
  data_as_of?: string | null; freshness?: Record<string, unknown>; limitations?: string[];
  trace_id?: string; policy_version?: string; data_sha256?: string[];
};

const base = process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000";
const cache = new Map<string, { expires: number; value: unknown }>();
export function clearApiCache() { cache.clear(); }

export class ApiFault extends Error {
  status: number;
  code: string;
  traceId?: string;
  constructor(status: number, code: string, message: string, traceId?: string) {
    super(message); this.status = status; this.code = code; this.traceId = traceId;
  }
}

async function request<T>(path: string, session: Session, init?: RequestInit): Promise<T> {
  const headers = new Headers(init?.headers);
  headers.set("Authorization", `Bearer ${session.token}`);
  headers.set("X-Active-Tenant", session.tenant);
  if (init?.body) headers.set("Content-Type", "application/json");
  let response: Response;
  try { response = await fetch(`${base}${path}`, { ...init, headers, cache: "no-store" }); }
  catch { throw new ApiFault(0, "unavailable", "API is unavailable. Start the local API and database."); }
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    const err = body?.error ?? {};
    throw new ApiFault(response.status, err.code ?? "request_failed", err.message ?? body?.detail ?? "Request failed.", err.trace_id);
  }
  return body as T;
}

export async function apiGet<T>(path: string, session: Session, options: { asOf?: string | null; cacheMs?: number } = {}): Promise<T> {
  const key = `${session.tenant}|${options.asOf ?? "latest"}|${path}`;
  const cached = cache.get(key);
  if (cached && cached.expires > Date.now()) return cached.value as T;
  const value = await request<T>(path, session);
  if (options.cacheMs) cache.set(key, { expires: Date.now() + options.cacheMs, value });
  return value;
}
export async function apiPost<T>(path: string, session: Session, payload: unknown, idempotencyKey: string): Promise<T> {
  return request<T>(path, session, { method: "POST", headers: { "Idempotency-Key": idempotencyKey }, body: JSON.stringify(payload) });
}
export const newIdempotencyKey = () => typeof crypto !== "undefined" && "randomUUID" in crypto ? crypto.randomUUID() : `${Date.now()}-${Math.random()}`;

export function prettyDate(value: unknown): string { return value ? new Date(String(value)).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short", timeZone: "UTC" }) + " UTC" : "Unknown"; }
export function fmt(value: unknown, suffix = ""): string { return value === null || value === undefined ? "Unknown" : `${value}${suffix}`; }
