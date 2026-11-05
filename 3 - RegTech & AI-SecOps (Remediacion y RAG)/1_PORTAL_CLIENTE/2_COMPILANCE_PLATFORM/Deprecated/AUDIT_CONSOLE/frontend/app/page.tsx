"use client";

/**
 * AUDIT_CONSOLE — Dashboard Principal
 *
 * Integra los 5 módulos de seguridad con el motor SSE del backend.
 * ZERO-TRUST: Solo envía client_id + script_id al API.
 */

import { useState, useCallback } from "react";
import { useSSE } from "@/app/hooks/useSSE";
import { ModuleCard, type ScriptDef } from "@/components/ModuleCard";
import { Terminal } from "@/components/Terminal";
import { StatusBadge } from "@/components/StatusBadge";
import { ClientSelector } from "@/components/ClientSelector";

// ──────────────────────────────────────────────────────────────────
// DEFINICIÓN DE MÓDULOS
// ──────────────────────────────────────────────────────────────────

interface ModuleDef {
  moduleNumber: string;
  title: string;
  description: string;
  icon: string;
  iconClass: string;
  accentClass: string;
  moduleEndpoint: string;
  scripts: ScriptDef[];
}

const MODULES: ModuleDef[] = [
  {
    moduleNumber: "01",
    title: "Auditor de Cumplimiento",
    description:
      "Análisis estático AST contra ENS Alta, NIS2 y CRA. Generación de SBOM con detección de CVEs en dependencias.",
    icon: "🛡",
    iconClass: "icon-cyan",
    accentClass: "accent-cyan",
    moduleEndpoint: "audit",
    scripts: [
      {
        scriptId: "compliance_audit",
        label: "ai_compliance_auditor.py",
        riskLevel: "LOW",
        requiresAdmin: false,
      },
      {
        scriptId: "generate_sbom",
        label: "generate_sbom.py",
        riskLevel: "LOW",
        requiresAdmin: false,
      },
    ],
  },
  {
    moduleNumber: "02",
    title: "Centro de Hardening",
    description:
      "Bastionado del sistema según ENS Alta y DISA STIG. Hardening VPS Linux. Requiere privilegios elevados.",
    icon: "🔒",
    iconClass: "icon-violet",
    accentClass: "accent-violet",
    moduleEndpoint: "hardening",
    scripts: [
      {
        scriptId: "bunker_init_alta",
        label: "bunker_init_alta.ps1",
        riskLevel: "CRITICAL",
        requiresAdmin: true,
      },
      {
        scriptId: "disa_stig",
        label: "disa_stig_hardening.ps1",
        riskLevel: "CRITICAL",
        requiresAdmin: true,
      },
      {
        scriptId: "harden_vps",
        label: "harden_vps.sh",
        riskLevel: "HIGH",
        requiresAdmin: true,
      },
    ],
  },
  {
    moduleNumber: "03",
    title: "Simulador de Caos",
    description:
      "Tests de resiliencia chaos engineering y simulación de ataques DDoS. Solo para entornos de laboratorio aislados.",
    icon: "⚡",
    iconClass: "icon-orange",
    accentClass: "accent-orange",
    moduleEndpoint: "chaos",
    scripts: [
      {
        scriptId: "chaos_tests",
        label: "15_run_chaos_tests.ps1",
        riskLevel: "HIGH",
        requiresAdmin: false,
      },
      {
        scriptId: "ddos_simulator",
        label: "ddos_simulator.py",
        riskLevel: "HIGH",
        requiresAdmin: false,
      },
    ],
  },
  {
    moduleNumber: "04",
    title: "Compilador Inmutable",
    description:
      "Pipeline de compilación con Nuitka. Genera binario inmutable firmado. Pre-build: assets, nonces CSP e integridad.",
    icon: "⬡",
    iconClass: "icon-green",
    accentClass: "accent-green",
    moduleEndpoint: "compiler",
    scripts: [
      {
        scriptId: "build_bunker",
        label: "build_nuitka.py",
        riskLevel: "MEDIUM",
        requiresAdmin: false,
      },
      {
        scriptId: "pre_build",
        label: "pre_build_pipeline.ps1",
        riskLevel: "LOW",
        requiresAdmin: false,
      },
    ],
  },
  {
    moduleNumber: "05",
    title: "RAG & Backups",
    description:
      "Ingestión y chunking para el pipeline RAG. Backup cifrado AES-256-GCM con verificación HMAC-SHA256.",
    icon: "◈",
    iconClass: "icon-cyan",
    accentClass: "accent-cyan",
    moduleEndpoint: "rag-backup",
    scripts: [
      {
        scriptId: "rag_ingestion",
        label: "rag_ingestion_pipeline.py",
        riskLevel: "LOW",
        requiresAdmin: false,
      },
      {
        scriptId: "secure_backup",
        label: "bunker_secure_backup.py",
        riskLevel: "MEDIUM",
        requiresAdmin: false,
      },
    ],
  },
];

// ──────────────────────────────────────────────────────────────────
// COMPONENTE PRINCIPAL
// ──────────────────────────────────────────────────────────────────

export default function DashboardPage() {
  const [clientId, setClientId]           = useState("E:\\PROYECTOS IA\\AUDITORIAS\\PRODUCTION-READY");
  const [activeModule, setActiveModule]   = useState<string | null>(null);
  const [activeScriptId, setActiveScriptId] = useState<string | null>(null);

  const { state, execute, abort } = useSSE();

  // ── Handler de ejecución ────────────────────────────────────────
  const handleRun = useCallback(
    (moduleEndpoint: string, scriptId: string) => {
      setActiveModule(moduleEndpoint);
      setActiveScriptId(scriptId);
      execute(moduleEndpoint, clientId, scriptId);
    },
    [clientId, execute]
  );

  // ── Estadísticas del dashboard ──────────────────────────────────
  const totalScripts = MODULES.reduce((acc, m) => acc + m.scripts.length, 0);
  const criticalCount = MODULES.flatMap((m) => m.scripts).filter(
    (s) => s.riskLevel === "CRITICAL"
  ).length;

  const nowStr = new Date().toLocaleString("es-ES", {
    day: "2-digit", month: "2-digit", year: "numeric",
    hour: "2-digit", minute: "2-digit",
  });

  return (
    <div>
      {/* ═══════════════════════════════════════════════════════════
          TOPBAR
      ═══════════════════════════════════════════════════════════ */}
      <header className="topbar" role="banner">
        <div className="topbar-logo">
          <div className="topbar-logo-icon" aria-hidden="true">⬡</div>
          <div>
            <div className="topbar-title">Audit_Console</div>
            <div className="topbar-subtitle">BUNKEROS SECURITY DASHBOARD v1.0</div>
          </div>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: "1.25rem" }}>
          <ClientSelector
            value={clientId}
            onChange={setClientId}
            disabled={state.status === "RUNNING"}
          />

          <div className="live-indicator">
            <span className="live-dot" aria-hidden="true" />
            ONLINE
          </div>
        </div>
      </header>

      {/* ═══════════════════════════════════════════════════════════
          CONTENIDO PRINCIPAL
      ═══════════════════════════════════════════════════════════ */}
      <main className="app-container" style={{ paddingTop: "1.5rem", paddingBottom: "3rem" }}>

        {/* ── Stats bar ─────────────────────────────────────────── */}
        <div className="stats-bar" role="region" aria-label="Estadísticas del sistema">
          <div className="stat-item">
            <span className="stat-value">5</span>
            <span className="stat-label">Módulos</span>
          </div>
          <div className="stat-divider" aria-hidden="true" />
          <div className="stat-item">
            <span className="stat-value">{totalScripts}</span>
            <span className="stat-label">Scripts</span>
          </div>
          <div className="stat-divider" aria-hidden="true" />
          <div className="stat-item">
            <span className="stat-value" style={{ color: "var(--risk-critical)" }}>
              {criticalCount}
            </span>
            <span className="stat-label">Critical</span>
          </div>
          <div className="stat-divider" aria-hidden="true" />
          <div className="stat-item">
            <StatusBadge status={state.status} size="md" />
            <span className="stat-label">Estado</span>
          </div>
          <div className="stat-divider" aria-hidden="true" />
          <div className="stat-item" style={{ marginLeft: "auto" }}>
            <span
              className="stat-value"
              style={{ fontSize: "0.7rem", color: "var(--text-muted)", fontWeight: 400 }}
            >
              {nowStr}
            </span>
            <span className="stat-label">Sesión</span>
          </div>
        </div>

        {/* ── Sección: Módulos ──────────────────────────────────── */}
        <div className="section-header" role="heading" aria-level={1}>
          <span className="section-header-text">MÓDULOS DE SEGURIDAD</span>
          <div className="section-header-line" aria-hidden="true" />
          <span
            className="section-header-text"
            style={{ fontFamily: "var(--font-mono)", color: "var(--neon-cyan)", opacity: 0.7 }}
          >
            CLIENT: {clientId.toUpperCase()}
          </span>
        </div>

        {/* ── Grid de 5 módulos ─────────────────────────────────── */}
        <section
          className="modules-grid"
          aria-label="Módulos de seguridad disponibles"
        >
          {MODULES.map((mod) => (
            <ModuleCard
              key={mod.moduleEndpoint}
              {...mod}
              activeScriptId={
                activeModule === mod.moduleEndpoint ? activeScriptId : null
              }
              status={activeModule === mod.moduleEndpoint ? state.status : "IDLE"}
              onRun={handleRun}
              disabled={state.status === "RUNNING" && activeModule !== mod.moduleEndpoint}
            />
          ))}
        </section>

        {/* ── Sección: Terminal ─────────────────────────────────── */}
        <div className="section-header">
          <span className="section-header-text">CONSOLA DE EJECUCIÓN</span>
          <div className="section-header-line" aria-hidden="true" />
          {state.status === "RUNNING" && (
            <button
              id="btn-abort-execution"
              onClick={abort}
              className="run-btn run-btn-danger"
              aria-label="Abortar ejecución actual"
            >
              ⬛ ABORT
            </button>
          )}
        </div>

        {/* Terminal con logs SSE en tiempo real */}
        <Terminal
          logs={state.logs}
          status={state.status}
          error={state.error}
          title={
            activeModule && activeScriptId
              ? `${activeModule}/${activeScriptId}`
              : "console"
          }
        />

        {/* Meta info si hay ejecución activa */}
        {state.meta && (
          <div
            style={{
              display: "flex",
              gap: "1rem",
              alignItems: "center",
              padding: "0.5rem 0.75rem",
              background: "rgba(0, 212, 255, 0.04)",
              border: "1px solid var(--border-subtle)",
              borderRadius: "8px",
              marginTop: "0.5rem",
              fontFamily: "var(--font-mono)",
              fontSize: "0.65rem",
              color: "var(--text-muted)",
            }}
            role="status"
            aria-live="polite"
          >
            <span>
              SCRIPT: <span style={{ color: "var(--neon-cyan)" }}>{state.meta.label}</span>
            </span>
            <span>|</span>
            <span>
              RIESGO:{" "}
              <span
                style={{
                  color:
                    state.meta.riskLevel === "CRITICAL"
                      ? "var(--risk-critical)"
                      : state.meta.riskLevel === "HIGH"
                      ? "var(--risk-high)"
                      : state.meta.riskLevel === "MEDIUM"
                      ? "var(--risk-medium)"
                      : "var(--risk-low)",
                  fontWeight: 700,
                }}
              >
                {state.meta.riskLevel}
              </span>
            </span>
            {state.meta.requiresAdmin && (
              <>
                <span>|</span>
                <span style={{ color: "var(--risk-high)" }}>⚡ ADMIN REQUIRED</span>
              </>
            )}
          </div>
        )}
      </main>

      {/* ═══════════════════════════════════════════════════════════
          FOOTER
      ═══════════════════════════════════════════════════════════ */}
      <footer
        style={{
          textAlign: "center",
          padding: "1.5rem",
          borderTop: "1px solid var(--border-subtle)",
          fontFamily: "var(--font-mono)",
          fontSize: "0.6rem",
          color: "var(--text-muted)",
          letterSpacing: "0.1em",
        }}
        role="contentinfo"
      >
        <span>AUDIT_CONSOLE v1.0 · ZERO-TRUST ARCHITECTURE · ENS ALTA · NIS2 · CRA</span>
        <span style={{ margin: "0 0.75rem", color: "var(--border-subtle)" }}>|</span>
        <span style={{ color: "var(--neon-cyan)", opacity: 0.5 }}>
          API: {process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000"}
        </span>
      </footer>
    </div>
  );
}
