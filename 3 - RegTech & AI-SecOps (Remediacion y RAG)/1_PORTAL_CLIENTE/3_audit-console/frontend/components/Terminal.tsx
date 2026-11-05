"use client";

import { useEffect, useRef } from "react";
import type { LogLine, ExecStatus } from "@/app/hooks/useSSE";

interface TerminalProps {
  logs: LogLine[];
  status: ExecStatus;
  title?: string;
  error?: string | null;
}

const lineTypeClass: Record<LogLine["type"], string> = {
  log:     "",
  info:    "terminal-line-info",
  success: "terminal-line-success",
  error:   "terminal-line-error",
  warn:    "terminal-line-warn",
  dim:     "terminal-line-dim",
};

export function Terminal({ logs, status, title = "console", error }: TerminalProps) {
  const bodyRef = useRef<HTMLDivElement>(null);

  // Auto-scroll al final en cada línea nueva
  useEffect(() => {
    if (bodyRef.current) {
      bodyRef.current.scrollTop = bodyRef.current.scrollHeight;
    }
  }, [logs]);

  return (
    <div className="terminal-wrapper" role="log" aria-label="Consola de ejecución">
      {/* ── Barra superior estilo macOS ───────────────────────── */}
      <div className="terminal-header">
        <div className="terminal-dots">
          <span className="terminal-dot terminal-dot-red"   aria-hidden="true" />
          <span className="terminal-dot terminal-dot-yellow" aria-hidden="true" />
          <span className="terminal-dot terminal-dot-green"  aria-hidden="true" />
        </div>

        <span className="terminal-title">
          {title} — {status}
        </span>

        <span
          style={{
            fontFamily: "var(--font-mono)",
            fontSize: "0.6rem",
            color: logs.length > 0 ? "var(--neon-green)" : "var(--text-muted)",
          }}
        >
          {logs.length} líneas
        </span>
      </div>

      {/* ── Cuerpo del terminal ───────────────────────────────── */}
      <div className="terminal-body" ref={bodyRef}>
        {logs.length === 0 && status === "IDLE" ? (
          <div className="terminal-empty">
            <span style={{ fontSize: "1.5rem" }}>⬡</span>
            <span>Esperando ejecución...</span>
            <span style={{ opacity: 0.5 }}>
              Selecciona un cliente y pulsa un script para comenzar
            </span>
          </div>
        ) : (
          <>
            {logs.map((line) => (
              <span
                key={line.id}
                className={`terminal-line ${lineTypeClass[line.type]}`}
              >
                {line.text || "\u00A0"}
              </span>
            ))}

            {/* Error display */}
            {error && status === "ERROR" && (
              <span className="terminal-line terminal-line-error">
                {`\n✗ FATAL: ${error}`}
              </span>
            )}

            {/* Cursor parpadeante solo cuando está corriendo */}
            {status === "RUNNING" && (
              <span aria-hidden="true">
                <span className="terminal-prompt">❯</span>
                <span className="terminal-cursor" />
              </span>
            )}

            {/* Mensaje de cierre */}
            {status === "DONE" && (
              <span className="terminal-line terminal-line-success">
                {"\n─────────────────────────────────────────────────\n"}
                {"✓ Proceso completado. Stream cerrado."}
              </span>
            )}
          </>
        )}
      </div>
    </div>
  );
}
