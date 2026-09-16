import { useState } from 'react';
import { Shield, Download, ArrowLeft, Loader2, ShieldCheck, ShieldAlert, Copy, Check, CheckCircle2, AlertTriangle } from 'lucide-react';
import { downloadCasePdf } from '../utils/pdfExport';

export default function SimpleView({ data, onBack }) {
  const [isExporting, setIsExporting] = useState(false);
  const [copied, setCopied] = useState(false);

  const isDanger = data.score > 50;
  const isDlpActive = data.dlp_security?.masking_active !== false && data.dlp_masking !== false;

  const handleExport = async () => {
    if (!data.case_id) {
      alert('No Case ID available for certified PDF export.');
      return;
    }
    setIsExporting(true);
    try {
      await downloadCasePdf(data.case_id);
    } catch (err) {
      console.error('Export error:', err);
      alert(err.message || 'Failed to download PDF report');
    } finally {
      setIsExporting(false);
    }
  };

  const handleCopyCaseId = () => {
    if (data.case_id) {
      navigator.clipboard.writeText(data.case_id);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <div className="w-full max-w-2xl mx-auto flex flex-col gap-4 sm:gap-6 animate-in fade-in slide-in-from-bottom-4 duration-500 mt-4 sm:mt-8 pb-10">
      
      {/* Top Navigation & Case Bar */}
      <div className="flex items-center justify-between gap-3 bg-[#0f111a] backdrop-blur-xl border border-zinc-800 rounded-xl p-3 px-4 shadow-[0_0_20px_rgba(0,0,0,0.8)]">
        {onBack ? (
          <button
            onClick={onBack}
            className="flex items-center gap-1.5 px-3 py-1 rounded-lg bg-zinc-900 hover:bg-zinc-800 text-zinc-300 hover:text-white border border-zinc-700/60 transition-colors text-xs font-bold uppercase tracking-wider"
          >
            <ArrowLeft className="w-3.5 h-3.5" />
            <span>Back</span>
          </button>
        ) : <div />}

        <div className="flex items-center gap-2">
          <button
            onClick={handleCopyCaseId}
            className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-zinc-950 border border-zinc-800 hover:border-cyan-500/40 text-cyan-400 font-mono text-xs font-bold transition-colors group"
            title="Click to copy Case ID"
          >
            <span>{data.case_id || 'CAS-IN-MEMORY'}</span>
            {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3 text-zinc-500 group-hover:text-cyan-300" />}
          </button>

          <div className={`flex items-center gap-1 px-2 py-0.5 rounded-md border text-[10px] font-bold uppercase tracking-wider ${
            isDlpActive
              ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
              : 'bg-rose-500/10 text-rose-400 border-rose-500/30'
          }`}>
            {isDlpActive ? <ShieldCheck className="w-3 h-3 text-emerald-400" /> : <ShieldAlert className="w-3 h-3 text-rose-400" />}
            <span>{isDlpActive ? 'DLP Active' : 'Unmasked'}</span>
          </div>
        </div>
      </div>

      {/* Big Status Banner */}
      <div className={`${isDanger ? 'bg-rose-500/10 border-rose-500/30 shadow-[0_0_30px_rgba(244,63,94,0.1)] hover:border-rose-500/50' : 'bg-emerald-500/10 border-emerald-500/30 shadow-[0_0_30px_rgba(16,185,129,0.1)] hover:border-emerald-500/50'} border rounded-2xl p-6 sm:p-8 flex flex-col items-center text-center transition-colors`}>
        <div className={`w-16 h-16 sm:w-20 sm:h-20 rounded-full flex items-center justify-center mb-4 sm:mb-6 ${isDanger ? 'bg-rose-500/20 text-rose-500' : 'bg-emerald-500/20 text-emerald-500'}`}>
          <Shield className="w-8 h-8 sm:w-10 sm:h-10" />
          {isDanger && (
            <div className="absolute">
              <AlertTriangle className="w-10 h-10 sm:w-12 sm:h-12 opacity-50 stroke-1" />
            </div>
          )}
        </div>
        
        <h2 className={`text-xl sm:text-2xl font-black tracking-wide mb-2 px-2 ${isDanger ? 'text-rose-500' : 'text-emerald-500'}`}>
          {isDanger ? 'MALICIOUS EMAIL DETECTED' : 'EMAIL IS SAFE'}
        </h2>
        <p className="text-zinc-300 text-xs sm:text-sm max-w-md mx-auto leading-relaxed px-2">
          {isDanger 
            ? 'This email is attempting to steal your credentials by impersonating a trusted financial institution. Do not interact with it.'
            : 'We found no threats. The sender is verified and the content looks standard.'}
        </p>

        <div className="mt-6 sm:mt-8 flex items-center gap-3 sm:gap-4 bg-zinc-950 border border-zinc-800 rounded-lg px-4 sm:px-6 py-2 sm:py-3 w-fit">
          <span className="text-[10px] sm:text-xs font-bold uppercase text-zinc-500 tracking-wider">Assigned Risk</span>
          <div className="w-px h-5 sm:h-6 bg-zinc-800"></div>
          <span className={`text-lg sm:text-xl font-black ${isDanger ? 'text-rose-500' : 'text-emerald-500'}`}>
            {data.score} <span className="text-[10px] sm:text-xs text-zinc-600 font-medium">/ 100</span>
          </span>
        </div>
      </div>

      {/* Actions & Advisory Section */}
      <div className="flex flex-col gap-3">
        {/* Recommended Action Advisory Callout (Read-Only SOC Guidance) */}
        <div className={`p-4 sm:p-5 rounded-2xl border flex items-start gap-3.5 text-left transition-colors ${
        isDanger 
          ? 'bg-rose-950/40 border-rose-500/40 text-rose-300 shadow-[0_0_20px_rgba(244,63,94,0.1)]' 
          : 'bg-emerald-950/40 border-emerald-500/40 text-emerald-300 shadow-[0_0_20px_rgba(16,185,129,0.1)]'
      }`}>
        {isDanger ? (
          <ShieldAlert className="w-6 h-6 text-rose-400 shrink-0 mt-0.5" />
        ) : (
          <CheckCircle2 className="w-6 h-6 text-emerald-400 shrink-0 mt-0.5" />
        )}
        <div className="flex-1">
          <div className="flex items-center gap-2">
            <span className="text-xs sm:text-sm font-bold uppercase tracking-wider">
              {isDanger ? 'Recommended Incident Response' : 'Forensic Delivery Advisory'}
            </span>
            <span className={`text-[9px] font-bold uppercase px-2 py-0.5 rounded-full border ${
              isDanger ? 'bg-rose-500/20 text-rose-300 border-rose-500/40' : 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
            }`}>
              {isDanger ? 'Action Required' : 'Safe to Proceed'}
            </span>
          </div>
          <p className="text-xs sm:text-sm text-zinc-300 mt-1.5 leading-relaxed">
            {isDanger 
              ? 'Recommended Action: Quarantine via Corporate Mail Gateway / Boundary Firewall. Isolate client endpoint and block sender domain at perimeter DNS.'
              : 'Recommended Action: Clean transmission verified. Message meets cryptographic integrity standards and is authorized for standard delivery.'}
          </p>
        </div>
      </div>

        {/* Download PDF / Export Certified Report Button */}
        <button
          onClick={handleExport}
          disabled={isExporting}
          className="w-full bg-zinc-950 hover:bg-cyan-950/40 text-cyan-300 hover:text-white border border-cyan-500/40 hover:border-cyan-400 font-bold py-3 sm:py-3.5 rounded-xl shadow-[0_0_15px_rgba(34,211,238,0.15)] transition-all flex items-center justify-center gap-2 text-xs sm:text-sm uppercase tracking-wider"
        >
          {isExporting ? (
            <>
              <Loader2 className="w-4 h-4 animate-spin text-cyan-400" />
              <span>Generating Certified Platypus PDF...</span>
            </>
          ) : (
            <>
              <Download className="w-4 h-4 text-cyan-400" />
              <span>Export Certified Forensic Report (PDF)</span>
            </>
          )}
        </button>
      </div>
      
    </div>
  );
}
