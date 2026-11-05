"use client";

import { useState } from "react";

interface ClientSelectorProps {
  value: string;
  onChange: (clientId: string) => void;
  disabled?: boolean;
}

const PRESETS = [
  {
    id: "prod",
    label: "⬡ Tavilga (Prod)",
    path: "E:\\PROYECTOS IA\\AUDITORIAS\\PRODUCTION-READY",
    desc: "Target principal producción",
  },
  {
    id: "dev",
    label: "◈ BunkerOS (Dev)",
    path: "E:\\PROYECTOS IA\\AUDITORIAS",
    desc: "Target entorno desarrollo",
  },
  {
    id: "rag",
    label: "⚡ Hybrid RAG",
    path: "E:\\PROYECTOS IA\\AUDITORIAS\\PRODUCTION-READY\\Hybrid RAG",
    desc: "Target módulo RAG",
  },
];

export function ClientSelector({ value, onChange, disabled = false }: ClientSelectorProps) {
  const [isCustomMode, setIsCustomMode] = useState(false);

  const handleSelectPreset = (path: string) => {
    onChange(path);
  };

  return (
    <div className="client-selector-container">
      <div className="client-selector-header">
        <span className="client-selector-label">
          <span className="client-selector-icon">📁</span> TARGET AUDIT PATH (CLIENT)
        </span>
        <div className="client-selector-presets">
          {PRESETS.map((preset) => {
            const isSelected = value.toLowerCase() === preset.path.toLowerCase();
            return (
              <button
                key={preset.id}
                type="button"
                className={`preset-chip ${isSelected ? "preset-chip-active" : ""}`}
                onClick={() => handleSelectPreset(preset.path)}
                disabled={disabled}
                title={preset.desc}
              >
                {preset.label}
              </button>
            );
          })}
        </div>
      </div>

      <div className="client-input-wrapper">
        <span className="client-input-prefix">PATH &gt;</span>
        <input
          id="client-selector"
          className="client-path-input"
          type="text"
          value={value}
          onChange={(e) => onChange(e.target.value)}
          disabled={disabled}
          aria-label="Ruta del cliente objetivo"
          placeholder="Escribe o pega cualquier ruta absoluta (ej. C:\Proyectos\ClienteX)"
          spellCheck={false}
        />
        {value && !disabled && (
          <button
            type="button"
            className="client-clear-btn"
            onClick={() => onChange("")}
            title="Limpiar ruta"
          >
            ✕
          </button>
        )}
      </div>
    </div>
  );
}

