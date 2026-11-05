"use client";

import type { ExecStatus } from "@/app/hooks/useSSE";

interface StatusBadgeProps {
  status: ExecStatus;
  size?: "sm" | "md";
}

const config: Record<ExecStatus, { label: string; cssClass: string; dot: string }> = {
  IDLE:    { label: "IDLE",    cssClass: "status-idle",    dot: "●" },
  RUNNING: { label: "RUNNING", cssClass: "status-running", dot: "◎" },
  DONE:    { label: "DONE",    cssClass: "status-done",    dot: "✓" },
  ERROR:   { label: "ERROR",   cssClass: "status-error",   dot: "✗" },
};

export function StatusBadge({ status, size = "sm" }: StatusBadgeProps) {
  const { label, cssClass, dot } = config[status];

  return (
    <span
      className={`status-badge ${cssClass}`}
      role="status"
      aria-label={`Estado: ${label}`}
    >
      <span
        aria-hidden="true"
        style={{
          display: "inline-block",
          animation: status === "RUNNING" ? "pulse-dot 1.2s infinite" : "none",
        }}
      >
        {dot}
      </span>
      {size === "md" && <span>{label}</span>}
      {size === "sm" && label}
    </span>
  );
}
