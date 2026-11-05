"use client";

import type { ExecStatus } from "@/app/hooks/useSSE";
import { StatusBadge } from "./StatusBadge";

export interface ScriptDef {
  scriptId: string;
  label: string;
  riskLevel: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  requiresAdmin?: boolean;
}

interface ModuleCardProps {
  moduleNumber: string;
  title: string;
  description: string;
  icon: string;
  iconClass: string;       // "icon-cyan" | "icon-violet" | "icon-green" | "icon-orange"
  accentClass: string;     // "accent-cyan" | "accent-violet" | ...
  moduleEndpoint: string;  // "audit" | "hardening" | "chaos" | "compiler" | "rag-backup"
  scripts: ScriptDef[];
  activeScriptId: string | null;
  status: ExecStatus;
  onRun: (moduleEndpoint: string, scriptId: string) => void;
  disabled?: boolean;
}

const RISK_CLASS: Record<string, string> = {
  LOW:      "risk-low",
  MEDIUM:   "risk-medium",
  HIGH:     "risk-high",
  CRITICAL: "risk-critical",
};

const RISK_ICON: Record<string, string> = {
  LOW:      "◦",
  MEDIUM:   "◈",
  HIGH:     "⚠",
  CRITICAL: "⛔",
};

export function ModuleCard({
  moduleNumber,
  title,
  description,
  icon,
  iconClass,
  accentClass,
  moduleEndpoint,
  scripts,
  activeScriptId,
  status,
  onRun,
  disabled = false,
}: ModuleCardProps) {
  const isRunning = status === "RUNNING";

  return (
    <article className="module-card" aria-label={`Módulo ${moduleNumber}: ${title}`}>
      {/* Línea de acento superior */}
      <div className={`module-card-accent ${accentClass}`} aria-hidden="true" />

      {/* Header */}
      <div className="module-card-header">
        <div className={`module-card-icon ${iconClass}`} aria-hidden="true">
          {icon}
        </div>
        <span className="module-number" aria-label={`Módulo ${moduleNumber}`}>
          MOD-{moduleNumber}
        </span>
      </div>

      {/* Título y descripción */}
      <h2 className="module-card-title">{title}</h2>
      <p className="module-card-desc">{description}</p>

      {/* Lista de scripts */}
      <div className="script-list">
        {scripts.map((script) => {
          const isThisRunning = isRunning && activeScriptId === script.scriptId;
          const isAnyRunning  = isRunning;

          return (
            <button
              key={script.scriptId}
              id={`btn-${moduleEndpoint}-${script.scriptId}`}
              className={`script-btn ${isThisRunning ? "script-btn-running" : ""}`}
              onClick={() => onRun(moduleEndpoint, script.scriptId)}
              disabled={isAnyRunning || disabled}
              aria-busy={isThisRunning}
              aria-label={`Ejecutar ${script.label}`}
              title={
                script.requiresAdmin
                  ? "⚠ Requiere privilegios de Administrador"
                  : script.label
              }
            >
              {/* Nombre del script */}
              <span className="script-btn-label">
                {script.requiresAdmin && (
                  <span
                    style={{ color: "var(--risk-high)", marginRight: "0.3rem" }}
                    aria-hidden="true"
                    title="Requiere Admin"
                  >
                    ⚡
                  </span>
                )}
                {script.label}
              </span>

              {/* Badges y botón */}
              <span className="script-btn-right">
                <span className={`risk-badge ${RISK_CLASS[script.riskLevel]}`}>
                  {RISK_ICON[script.riskLevel]} {script.riskLevel}
                </span>

                {isThisRunning ? (
                  <StatusBadge status="RUNNING" />
                ) : (
                  <span className="run-btn run-btn-primary">
                    {isThisRunning ? (
                      <><span className="spinner" aria-hidden="true" /> Corriendo</>
                    ) : (
                      "▶ RUN"
                    )}
                  </span>
                )}
              </span>
            </button>
          );
        })}
      </div>
    </article>
  );
}
