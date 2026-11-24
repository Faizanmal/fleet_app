"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useSession } from "@/components/session-provider";
import type { Session } from "@/lib/api";

const nav = [["/", "Overview", "▦"], ["/copilot", "Copilot", "✳"], ["/devices", "Devices", "▤"], ["/insights", "Insights", "◈"], ["/actions", "Actions", "⇢"], ["/trust", "Trust & provenance", "⌘"], ["/observability", "Observability", "◌"]];
const tenants = [["acme-001", "Acme"], ["globex-002", "Globex"], ["initech-003", "Initech"]];
const roles = ["viewer", "operator", "approver", "admin"] as const;
export default function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname(); const { session, setSession } = useSession();
  const tenantName = tenants.find(([id]) => id === session.tenant)?.[1] ?? session.tenant;
  function switchSession(tenant: string, role: Session["role"]) {
    const token = role === "admin" && tenant === "acme-001" ? "demo-acme-admin" : `demo-${tenant}-${role}`;
    setSession({ tenant, role, token });
  }
  return <div className="app-frame">
    <a className="skip-link" href="#main-content">Skip to content</a>
    <aside className="sidebar" aria-label="Primary navigation">
      <Link className="brand" href="/"><span className="brand-mark">R</span><span>rayda<small>FLEET INTELLIGENCE</small></span></Link>
      <div className="workspace-label">WORKSPACE</div>
      <nav>{nav.map(([href, title, icon]) => <Link key={href} href={href} className={`nav-item ${pathname === href || (href !== "/" && pathname.startsWith(href)) ? "active" : ""}`} aria-current={pathname === href ? "page" : undefined}><span aria-hidden="true">{icon}</span>{title}</Link>)}</nav>
      <div className="sidebar-foot"><span className="tenant-dot" /> Historical telemetry<br/><small>Dataset · May–June 2026</small></div>
    </aside>
    <div className="main-column">
      <div className="historical-banner" role="note"><strong>HISTORICAL DEMO DATA</strong><span>Telemetry is from the pinned May–June 2026 dataset. No live fleet connection is active. All actions run in simulation only.</span></div>
      <header className="topbar">
        <div><span className="eyebrow">TENANT WORKSPACE</span><strong>{tenantName} <span className="muted">/</span> Fleet operations</strong></div>
        <div className="session-controls">
          <label>Tenant<select aria-label="Authorized demo tenant" value={session.tenant} onChange={e => switchSession(e.target.value, session.role)}>{tenants.map(([id,name]) => <option key={id} value={id}>{name}</option>)}</select></label>
          <label>Demo role<select aria-label="Development fixture role" value={session.role} onChange={e => switchSession(session.tenant, e.target.value as Session["role"])}>{roles.map(role => <option key={role} value={role}>{role}</option>)}</select></label>
          <span className="avatar" aria-hidden="true">{session.role[0].toUpperCase()}</span>
        </div>
      </header>
      <main id="main-content" tabIndex={-1}><div key={`${session.tenant}:${session.role}`}>{children}</div></main>
      <footer className="footer"><span>Historical telemetry · no live device connection</span><span>Fixture identity mode · {session.role}</span></footer>
    </div>
  </div>;
}
