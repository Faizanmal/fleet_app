"use client";

import { createContext, useContext, useMemo, useState, type ReactNode } from "react";
import { clearApiCache, type Session } from "@/lib/api";

type SessionState = { session: Session; setSession: (value: Session) => void };
const Context = createContext<SessionState | null>(null);
const initial: Session = { tenant: "acme-001", role: "viewer", token: "demo-acme-001-viewer" };
export function SessionProvider({ children }: { children: ReactNode }) {
  const [session, update] = useState<Session>(initial);
  const setSession = (value: Session) => { clearApiCache(); update(value); };
  return <Context.Provider value={useMemo(() => ({ session, setSession }), [session])}>{children}</Context.Provider>;
}
export function useSession() {
  const value = useContext(Context);
  if (!value) throw new Error("SessionProvider is missing");
  return value;
}
