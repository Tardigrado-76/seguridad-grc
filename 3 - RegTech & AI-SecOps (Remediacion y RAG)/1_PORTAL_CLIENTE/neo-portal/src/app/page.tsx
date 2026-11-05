import React from 'react';
import Link from 'next/link';

export default function Home() {
  return (
    <main className="min-h-screen bg-slate-950 text-slate-50 p-8 font-sans selection:bg-emerald-500/30">
      <div className="max-w-7xl mx-auto space-y-8">
        
        {/* Header */}
        <header className="flex items-center justify-between py-6 border-b border-slate-800/50">
          <div>
            <h1 className="text-3xl font-light tracking-tight text-white">Quantigrade <span className="font-semibold text-emerald-400">Core</span></h1>
            <p className="text-slate-400 mt-1 text-sm tracking-wide uppercase">C-Level Executive Dashboard</p>
          </div>
          <div className="flex items-center gap-4">
            <span className="px-3 py-1 text-xs font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 rounded-full">SYSTEM SECURE</span>
            <div className="w-10 h-10 rounded-full bg-slate-800 border border-slate-700 overflow-hidden">
               {/* Architect Avatar placeholder */}
               <div className="w-full h-full bg-gradient-to-br from-slate-700 to-slate-900 flex items-center justify-center text-xs font-bold">JRC</div>
            </div>
          </div>
        </header>

        {/* Bento Grid */}
        <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-4 gap-6 auto-rows-[160px]">
          
          {/* Card 1: Main Overview (Large) */}
          <div className="col-span-1 md:col-span-2 lg:col-span-2 row-span-2 rounded-3xl bg-slate-900 border border-slate-800 p-8 relative overflow-hidden group">
            <div className="absolute inset-0 bg-gradient-to-br from-emerald-500/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-500" />
            <h2 className="text-2xl font-medium mb-2">Security Posture</h2>
            <div className="text-6xl font-light text-emerald-400 mb-6">98.4%</div>
            <p className="text-slate-400 max-w-sm">All core systems, DORA compliance metrics, and NIS2 frameworks are operating optimally.</p>
            <div className="absolute bottom-8 right-8">
              <svg className="w-24 h-24 text-emerald-500/10" viewBox="0 0 24 24" fill="currentColor"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
            </div>
          </div>

          {/* Card 2: Active Agents */}
          <div className="col-span-1 rounded-3xl bg-slate-900 border border-slate-800 p-6 flex flex-col justify-between hover:border-slate-700 transition-colors">
            <h3 className="text-sm font-semibold tracking-wider text-slate-400 uppercase">LangGraph Agents</h3>
            <div>
              <div className="text-3xl font-light mb-1">3 <span className="text-lg text-slate-500">Active</span></div>
              <div className="flex gap-2 mt-4">
                <span className="w-2 h-2 rounded-full bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.8)] animate-pulse" />
                <span className="w-2 h-2 rounded-full bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.8)] animate-pulse delay-75" />
                <span className="w-2 h-2 rounded-full bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.8)] animate-pulse delay-150" />
              </div>
            </div>
          </div>

          {/* Card 3: RAG Engine */}
          <div className="col-span-1 lg:row-span-2 rounded-3xl bg-slate-900 border border-slate-800 p-6 hover:border-slate-700 transition-colors relative overflow-hidden">
            <div className="absolute top-0 right-0 w-32 h-32 bg-indigo-500/10 rounded-full blur-3xl -mr-16 -mt-16" />
            <h3 className="text-sm font-semibold tracking-wider text-slate-400 uppercase mb-4">Governance RAG</h3>
            <p className="text-sm text-slate-300 leading-relaxed mb-6">Powered by Qdrant Vector DB & LangChain. Real-time querying across all audit documents.</p>
            <button className="w-full py-3 rounded-xl bg-slate-800 text-sm font-medium hover:bg-slate-700 transition-colors border border-slate-700">Query Engine</button>
          </div>

          {/* Card 4: Audit Bunker */}
          <div className="col-span-1 rounded-3xl bg-slate-900 border border-slate-800 p-6 flex flex-col justify-between">
            <h3 className="text-sm font-semibold tracking-wider text-slate-400 uppercase">Audit Bunker</h3>
            <div className="flex items-end justify-between">
              <span className="text-2xl font-light text-slate-200">Locked</span>
              <svg className="w-6 h-6 text-slate-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/></svg>
            </div>
          </div>

          {/* Card 5: Vault Status */}
          <div className="col-span-1 md:col-span-2 rounded-3xl bg-gradient-to-r from-slate-900 to-slate-800 border border-slate-700 p-6 flex items-center justify-between hover:border-slate-600 transition-colors cursor-pointer">
            <div>
              <h3 className="text-sm font-semibold tracking-wider text-slate-400 uppercase mb-1">HashiCorp Vault</h3>
              <p className="text-slate-300">Secrets dynamically injected. Zero hardcoded tokens.</p>
            </div>
            <div className="h-10 w-10 rounded-full bg-emerald-500/20 flex items-center justify-center">
              <svg className="w-5 h-5 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7"/></svg>
            </div>
          </div>

        </div>
      </div>
    </main>
  );
}