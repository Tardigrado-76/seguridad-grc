import type { Metadata } from "next";
import { Inter, JetBrains_Mono } from "next/font/google";
import "./globals.css";

const inter = Inter({
  subsets: ["latin"],
  variable: "--font-inter",
  display: "swap",
});

const jetbrainsMono = JetBrains_Mono({
  subsets: ["latin"],
  variable: "--font-jetbrains",
  display: "swap",
});

export const metadata: Metadata = {
  title: "Audit_Console | BunkerOS Security Dashboard",
  description:
    "Panel de control unificado Zero-Trust para gestión centralizada de scripts de seguridad DevSecOps. " +
    "Módulos de Auditoría ENS Alta, Hardening, Simulación de Caos, Compilación Inmutable y Backups cifrados.",
  keywords: [
    "DevSecOps",
    "ENS Alta",
    "Zero-Trust",
    "Security Dashboard",
    "SBOM",
    "Hardening",
    "DISA STIG",
    "NIS2",
    "CRA",
  ],
  robots: "noindex, nofollow", // Panel interno — no indexar
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="es" className={`${inter.variable} ${jetbrainsMono.variable}`}>
      <body style={{ fontFamily: "var(--font-inter, var(--font-sans))" }}>
        {children}
      </body>
    </html>
  );
}
