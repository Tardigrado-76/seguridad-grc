"use client";

/**
 * useSSE — Custom hook para Server-Sent Events
 *
 * Maneja la conexión EventSource al backend FastAPI, procesa los
 * eventos SSE tipados (meta, log, status) y expone el estado de
 * ejecución al componente padre.
 *
 * ZERO-TRUST: Solo envía client_id + script_id. Nunca paths.
 */

import { useCallback, useRef, useState } from "react";

export type ExecStatus = "IDLE" | "RUNNING" | "DONE" | "ERROR";

export interface LogLine {
  id: number;
  text: string;
  type: "log" | "info" | "success" | "error" | "warn" | "dim";
}

export interface SSEState {
  status: ExecStatus;
  logs: LogLine[];
  meta: {
    label?: string;
    riskLevel?: string;
    requiresAdmin?: boolean;
  } | null;
  error: string | null;
}

const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

/** Clasifica una línea de log para asignarle color */
function classifyLine(text: string): LogLine["type"] {
  const t = text.toLowerCase();
  if (t.includes("✓") || t.includes("success") || t.includes("completado") || t.includes("done")) return "success";
  if (t.includes("✗") || t.includes("error") || t.includes("fail") || t.includes("exception")) return "error";
  if (t.includes("⚠") || t.includes("warn") || t.includes("timeout")) return "warn";
  if (t.includes("▶") || t.includes("cmd:") || t.includes("cwd:")) return "info";
  if (text.startsWith("─") || text.trim() === "") return "dim";
  return "log";
}

let lineCounter = 0;

export function useSSE() {
  const [state, setState] = useState<SSEState>({
    status: "IDLE",
    logs: [],
    meta: null,
    error: null,
  });

  const eventSourceRef = useRef<EventSource | null>(null);

  /** Cancela cualquier stream SSE activo */
  const abort = useCallback(() => {
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
      eventSourceRef.current = null;
    }
  }, []);

  /**
   * Inicia la ejecución de un script via POST + SSE stream.
   *
   * SEGURIDAD: Solo envía client_id y script_id al backend.
   * La resolución de rutas ocurre exclusivamente en el servidor.
   */
  const execute = useCallback(
    async (moduleEndpoint: string, clientId: string, scriptId: string) => {
      // Cancelar stream previo si existe
      abort();

      setState({
        status: "RUNNING",
        logs: [],
        meta: null,
        error: null,
      });

      try {
        // ── 1. POST para iniciar la ejecución ─────────────────────
        // EventSource no soporta POST, usamos fetch + ReadableStream
        const response = await fetch(
          `${API_BASE}/api/v1/${moduleEndpoint}/run`,
          {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              Accept: "text/event-stream",
            },
            body: JSON.stringify({
              client_id: clientId,
              script_id: scriptId,
            }),
          }
        );

        if (!response.ok) {
          const errData = await response.json().catch(() => ({}));
          throw new Error(
            errData?.detail ?? `HTTP ${response.status}: ${response.statusText}`
          );
        }

        if (!response.body) throw new Error("Response body is null");

        // ── 2. Leer el stream línea a línea ───────────────────────
        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let buffer = "";

        while (true) {
          const { done, value } = await reader.read();
          if (done) break;

          buffer += decoder.decode(value, { stream: true });
          const lines = buffer.split("\n");
          buffer = lines.pop() ?? "";

          for (const rawLine of lines) {
            const line = rawLine.trim();
            if (!line) continue;

            // Parsear eventos SSE: "event: TYPE" y "data: JSON"
            if (line.startsWith("event: ")) {
              // next line will be data
              continue;
            }

            if (line.startsWith("data: ")) {
              try {
                const payload = JSON.parse(line.slice(6));

                // Evento: meta
                if (payload.label !== undefined) {
                  setState((prev) => ({
                    ...prev,
                    meta: {
                      label: payload.label,
                      riskLevel: payload.risk_level,
                      requiresAdmin: payload.requires_admin,
                    },
                  }));
                  continue;
                }

                // Evento: status
                if (payload.status !== undefined) {
                  const newStatus = payload.status as ExecStatus;
                  setState((prev) => ({
                    ...prev,
                    status: newStatus,
                    error: newStatus === "ERROR" ? (payload.message ?? "Error desconocido") : null,
                  }));
                  continue;
                }

                // Evento: log
                if (payload.line !== undefined) {
                  const text: string = payload.line;
                  setState((prev) => ({
                    ...prev,
                    logs: [
                      ...prev.logs,
                      {
                        id: ++lineCounter,
                        text,
                        type: classifyLine(text),
                      },
                    ],
                  }));
                }
              } catch {
                // línea no es JSON válido — ignorar silenciosamente
              }
            }
          }
        }
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : "Error de conexión";
        setState((prev) => ({
          ...prev,
          status: "ERROR",
          error: message,
          logs: [
            ...prev.logs,
            {
              id: ++lineCounter,
              text: `✗ ${message}`,
              type: "error",
            },
          ],
        }));
      }
    },
    [abort]
  );

  return { state, execute, abort };
}
