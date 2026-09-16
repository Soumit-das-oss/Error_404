import { useState, useEffect } from 'react';
import { 
  ShieldCheck, ShieldAlert, AlertTriangle, AlertCircle, 
  CheckCircle2, RefreshCw, Search, ArrowRight, Download, 
  Radio, Loader2, Copy, Check, UploadCloud, Trash2, X
} from 'lucide-react';
import { downloadCasePdf } from '../utils/pdfExport';

export default function Dashboard({ onSelectCase, onNewScan }) {
  const [cases, setCases] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [wiping, setWiping] = useState(false);
  const [wipeNotice, setWipeNotice] = useState(null);
  const [error, setError] = useState(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [verdictFilter, setVerdictFilter] = useState('ALL');
  const [loadingCaseId, setLoadingCaseId] = useState(null);
  const [downloadingCaseId, setDownloadingCaseId] = useState(null);
  const [copiedId, setCopiedId] = useState(null);

  const handleManualRefresh = async () => {
    setRefreshing(true);
    setError(null);
    try {
      const res = await fetch('http://localhost:8000/api/v1/cases?page=1&limit=25');
      if (!res.ok) {
        throw new Error(`Failed to fetch forensic cases (HTTP ${res.status})`);
      }
      const data = await res.json();
      setCases(data.items || []);
      setTotal(data.total || 0);
    } catch (err) {
      console.error('Fetch cases error:', err);
      setError(err.message || 'Target forensic backend [localhost:8000] is unavailable.');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  const handleEmergencyWipe = async () => {
    if (!window.confirm("EMERGENCY FORENSIC ACTION:\nAre you sure you want to flush all in-memory cases from volatile RAM?\n\nThis will zeroize all ephemeral evidence immediately.")) {
      return;
    }
    setWiping(true);
    setError(null);
    try {
      const res = await fetch('http://localhost:8000/api/v1/cases', {
        method: 'DELETE',
      });
      if (!res.ok) {
        throw new Error(`Failed to purge volatile RAM (HTTP ${res.status})`);
      }
      setCases([]);
      setTotal(0);
      setWipeNotice("Volatile RAM purged. Zero evidence remaining.");
      setTimeout(() => setWipeNotice(null), 5000);
    } catch (err) {
      console.error('Memory wipe error:', err);
      setError(err.message || 'Failed to purge volatile memory');
    } finally {
      setWiping(false);
    }
  };

  useEffect(() => {
    let active = true;
    fetch('http://localhost:8000/api/v1/cases?page=1&limit=25')
      .then((res) => {
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        return res.json();
      })
      .then((data) => {
        if (active) {
          setCases(data.items || []);
          setTotal(data.total || 0);
          setLoading(false);
        }
      })
      .catch((err) => {
        if (active) {
          console.error('Initial cases fetch error:', err);
          setError(err.message || 'Target forensic backend is unreachable');
          setLoading(false);
        }
      });
    return () => {
      active = false;
    };
  }, []);

  const handleCopy = (e, id) => {
    e.stopPropagation();
    navigator.clipboard.writeText(id);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const handleDownloadPdf = async (e, caseId) => {
    e.stopPropagation();
    setDownloadingCaseId(caseId);
    try {
      await downloadCasePdf(caseId);
    } catch (err) {
      alert(err.message || 'Failed to download PDF dossier');
    } finally {
      setDownloadingCaseId(null);
    }
  };

  const handleRowClick = async (caseId) => {
    setLoadingCaseId(caseId);
    try {
      await onSelectCase(caseId);
    } finally {
      setLoadingCaseId(null);
    }
  };

  // Filter and search
  const filteredCases = cases.filter((c) => {
    const verdict = (c.verdict || c.risk?.verdict || 'SAFE').toUpperCase();
    if (verdictFilter !== 'ALL' && !verdict.includes(verdictFilter)) {
      return false;
    }
    if (!searchQuery.trim()) return true;
    const q = searchQuery.toLowerCase();
    const caseId = (c.case_id || '').toLowerCase();
    const sender = (c.sender || c.sender_address || c.sender_display_name || '').toLowerCase();
    const subject = (c.subject || '').toLowerCase();
    return caseId.includes(q) || sender.includes(q) || subject.includes(q);
  });

  // Threat counts
  const maliciousCount = cases.filter((c) => (c.verdict || c.risk?.verdict || '').toUpperCase().includes('MALICIOUS')).length;
  const suspiciousCount = cases.filter((c) => (c.verdict || c.risk?.verdict || '').toUpperCase().includes('SUSPICIOUS')).length;
  const safeCount = cases.filter((c) => (c.verdict || c.risk?.verdict || '').toUpperCase() === 'SAFE').length;
  const dlpMaskedCount = cases.filter((c) => c.dlp_security?.masking_active !== false && c.dlp_masking !== false).length;

  const formatDate = (dateStr) => {
    if (!dateStr) return 'Recent';
    try {
      const d = new Date(dateStr);
      if (isNaN(d.getTime())) return dateStr;
      return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) + ' ' + d.toLocaleDateString([], { month: 'short', day: 'numeric' });
    } catch {
      return dateStr;
    }
  };

  return (
    <div className="w-full flex flex-col gap-6 animate-in fade-in duration-500 pb-12">
      
      {/* SOC HEADER & TELEMETRY SUMMARY */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 bg-[#0f111a] backdrop-blur-xl border border-slate-700/80 rounded-2xl p-5 sm:p-6 shadow-[0_0_20px_rgba(0,0,0,0.8)]">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <div className="w-2.5 h-2.5 rounded-full bg-emerald-500 animate-ping" />
            <span className="text-[10px] sm:text-xs font-mono font-bold uppercase tracking-widest text-emerald-400">
              Live In-Memory Forensic Case Store
            </span>
          </div>
          <h2 className="text-xl sm:text-2xl font-black tracking-wide text-white flex items-center gap-3">
            SOC Investigation Dashboard
            <span className="text-xs font-mono px-2.5 py-1 rounded bg-zinc-950 border border-zinc-800 text-zinc-400 font-semibold">
              FIFO Cap: 25
            </span>
          </h2>
          <p className="text-zinc-400 text-xs sm:text-sm mt-1">
            Zero-database, ephemeral digital forensic memory records with cryptographic tamper-proofing.
          </p>
        </div>

        <div className="flex items-center gap-2 sm:gap-3 shrink-0 flex-wrap sm:flex-nowrap">
          <button
            onClick={handleManualRefresh}
            disabled={refreshing || wiping}
            className="flex items-center gap-2 px-3.5 py-2 rounded-xl bg-zinc-950 hover:bg-zinc-900 border border-zinc-800 hover:border-cyan-500/40 text-zinc-300 hover:text-cyan-300 text-xs font-bold uppercase tracking-wider transition-all"
            title="Refresh In-Memory Cases"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin text-cyan-400' : ''}`} />
            <span>{refreshing ? 'Refreshing...' : 'Refresh'}</span>
          </button>

          <button
            onClick={handleEmergencyWipe}
            disabled={wiping || total === 0}
            className="flex items-center gap-2 px-3.5 py-2 rounded-xl bg-rose-950/40 hover:bg-rose-950/80 border border-rose-500/40 hover:border-rose-500 text-rose-300 hover:text-rose-200 text-xs font-bold uppercase tracking-wider transition-all shadow-[0_0_12px_rgba(244,63,94,0.15)] hover:shadow-[0_0_20px_rgba(244,63,94,0.3)] disabled:opacity-40 disabled:cursor-not-allowed"
            title="Emergency Zero-Trace Memory Wipe"
          >
            {wiping ? (
              <Loader2 className="w-3.5 h-3.5 animate-spin text-rose-400" />
            ) : (
              <Trash2 className="w-3.5 h-3.5 text-rose-400" />
            )}
            <span>Flush RAM Queue</span>
          </button>

          {onNewScan && (
            <button
              onClick={onNewScan}
              className="flex items-center gap-2 px-4 py-2 rounded-xl bg-gradient-to-r from-cyan-950 to-slate-900 border border-cyan-500/50 text-cyan-400 hover:text-cyan-300 hover:shadow-[0_0_20px_rgba(34,211,238,0.2)] text-xs font-bold uppercase tracking-wider transition-all hover:scale-105"
            >
              <UploadCloud className="w-4 h-4" />
              <span>Ingest Email</span>
            </button>
          )}
        </div>
      </div>

      {/* ZERO-TRACE PURGE NOTIFICATION */}
      {wipeNotice && (
        <div className="bg-emerald-950/90 border border-emerald-500/60 rounded-xl p-4 flex items-center justify-between gap-3 text-xs text-emerald-200 shadow-[0_0_25px_rgba(16,185,129,0.25)] animate-in fade-in slide-in-from-top-2 duration-300">
          <div className="flex items-center gap-2.5">
            <div className="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-ping" />
            <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0" />
            <span className="font-mono font-bold tracking-wide">{wipeNotice}</span>
          </div>
          <button
            onClick={() => setWipeNotice(null)}
            className="p-1 text-emerald-400 hover:text-emerald-200 transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      {/* BACKEND CONNECTIVITY ALERT */}
      {error && (
        <div className="bg-rose-950/80 border border-rose-500/50 rounded-xl p-4 flex items-center justify-between gap-3 text-xs text-rose-300 shadow-lg">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
            <span>{error}</span>
          </div>
          <button
            onClick={handleManualRefresh}
            className="px-3 py-1 bg-rose-900/60 hover:bg-rose-800 text-white rounded-lg font-mono text-[10px] uppercase font-bold transition-colors"
          >
            Retry
          </button>
        </div>
      )}

      {/* QUICK METRICS BAR */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 sm:gap-4">
        <div className="bg-[#0f111a] backdrop-blur-xl border border-slate-700/60 rounded-xl p-4 flex flex-col justify-between">
          <span className="text-[10px] sm:text-xs font-bold uppercase tracking-wider text-zinc-400">Total Cases</span>
          <div className="flex items-baseline justify-between mt-2">
            <span className="text-2xl sm:text-3xl font-black text-white">{total}</span>
            <span className="text-[10px] font-mono text-zinc-500">/ 25 in RAM</span>
          </div>
        </div>

        <div className="bg-[#0f111a] backdrop-blur-xl border border-rose-500/30 rounded-xl p-4 flex flex-col justify-between shadow-[0_0_15px_rgba(244,63,94,0.05)]">
          <div className="flex items-center justify-between">
            <span className="text-[10px] sm:text-xs font-bold uppercase tracking-wider text-rose-400">Malicious</span>
            <AlertTriangle className="w-4 h-4 text-rose-500" />
          </div>
          <div className="mt-2">
            <span className="text-2xl sm:text-3xl font-black text-rose-500">{maliciousCount}</span>
          </div>
        </div>

        <div className="bg-[#0f111a] backdrop-blur-xl border border-amber-500/30 rounded-xl p-4 flex flex-col justify-between shadow-[0_0_15px_rgba(245,158,11,0.05)]">
          <div className="flex items-center justify-between">
            <span className="text-[10px] sm:text-xs font-bold uppercase tracking-wider text-amber-400">Suspicious</span>
            <AlertCircle className="w-4 h-4 text-amber-400" />
          </div>
          <div className="mt-2">
            <span className="text-2xl sm:text-3xl font-black text-amber-400">{suspiciousCount}</span>
          </div>
        </div>

        <div className="bg-[#0f111a] backdrop-blur-xl border border-emerald-500/30 rounded-xl p-4 flex flex-col justify-between shadow-[0_0_15px_rgba(16,185,129,0.05)]">
          <div className="flex items-center justify-between">
            <span className="text-[10px] sm:text-xs font-bold uppercase tracking-wider text-emerald-400">Safe / DLP Active</span>
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="flex items-baseline justify-between mt-2">
            <span className="text-2xl sm:text-3xl font-black text-emerald-400">{safeCount}</span>
            <span className="text-[10px] font-mono text-emerald-400/80">{dlpMaskedCount} Masked</span>
          </div>
        </div>
      </div>

      {/* SEARCH AND VERDICT FILTERS */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-3 bg-[#0f111a] backdrop-blur-xl border border-slate-700/80 rounded-xl p-3 shadow-lg">
        <div className="relative w-full sm:w-80">
          <Search className="w-4 h-4 text-zinc-500 absolute left-3.5 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search Case ID, sender, subject..."
            className="w-full bg-zinc-950 border border-zinc-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-100 placeholder:text-zinc-600 focus:outline-none focus:border-cyan-500/50 font-mono"
          />
        </div>

        <div className="flex items-center gap-1.5 w-full sm:w-auto overflow-x-auto">
          {['ALL', 'MALICIOUS', 'SUSPICIOUS', 'SAFE'].map((tier) => (
            <button
              key={tier}
              onClick={() => setVerdictFilter(tier)}
              className={`px-3 py-1.5 rounded-lg text-[10px] font-bold uppercase tracking-wider transition-all shrink-0 ${
                verdictFilter === tier
                  ? tier === 'MALICIOUS'
                    ? 'bg-rose-500/20 text-rose-400 border border-rose-500/50'
                    : tier === 'SUSPICIOUS'
                    ? 'bg-amber-500/20 text-amber-400 border border-amber-500/50'
                    : tier === 'SAFE'
                    ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/50'
                    : 'bg-zinc-800 text-cyan-400 border border-cyan-500/50'
                  : 'bg-zinc-950 text-zinc-500 hover:text-zinc-300 border border-zinc-800/60'
              }`}
            >
              {tier}
            </button>
          ))}
        </div>
      </div>

      {/* CASES TABLE & CARDS */}
      {loading ? (
        <div className="bg-[#0f111a] backdrop-blur-xl border border-slate-700/80 rounded-2xl p-12 flex flex-col items-center justify-center text-center">
          <Loader2 className="w-8 h-8 text-cyan-400 animate-spin mb-3" />
          <p className="text-zinc-400 font-mono text-xs uppercase tracking-widest">Querying Active Memory Cases...</p>
        </div>
      ) : filteredCases.length === 0 ? (
        <div className="bg-[#0f111a] backdrop-blur-xl border border-slate-700/80 rounded-2xl p-12 flex flex-col items-center justify-center text-center">
          <div className="w-14 h-14 rounded-full bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center mb-4 shadow-[0_0_20px_rgba(34,211,238,0.15)]">
            <Radio className="w-7 h-7 text-cyan-400" />
          </div>
          <h3 className="text-base sm:text-lg font-bold text-slate-100 tracking-wide">
            {cases.length === 0 ? 'No Active In-Memory Cases' : 'No Matching Forensic Cases'}
          </h3>
          <p className="text-zinc-500 text-xs sm:text-sm max-w-md mt-1 mb-6 leading-relaxed">
            {cases.length === 0
              ? 'The zero-disk RAM FIFO store is empty. Ingest an email (.eml / .msg) to execute cryptographic and AI threat analysis.'
              : 'Try clearing your search query or verdict filters.'}
          </p>
          {cases.length === 0 && onNewScan && (
            <button
              onClick={onNewScan}
              className="flex items-center gap-2 px-5 py-2.5 rounded-xl bg-gradient-to-r from-cyan-950 to-slate-900 border border-cyan-500/50 text-cyan-400 hover:text-white text-xs font-black uppercase tracking-wider shadow-[0_0_20px_rgba(34,211,238,0.2)] hover:scale-105 transition-all"
            >
              <UploadCloud className="w-4 h-4" />
              <span>Ingest Email File</span>
            </button>
          )}
        </div>
      ) : (
        <>
          {/* DESKTOP RESPONSIVE TABLE */}
          <div className="hidden md:block bg-[#0f111a] backdrop-blur-xl border border-slate-700/80 rounded-2xl shadow-[0_0_20px_rgba(0,0,0,0.8)] overflow-hidden">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-zinc-800 bg-zinc-950/60 text-[10px] font-bold uppercase tracking-widest text-zinc-500">
                  <th className="py-3.5 px-5">Case ID</th>
                  <th className="py-3.5 px-4">Timestamp</th>
                  <th className="py-3.5 px-4">Sender & Subject</th>
                  <th className="py-3.5 px-4 text-center">Risk Score</th>
                  <th className="py-3.5 px-4">Verdict</th>
                  <th className="py-3.5 px-4">DLP Status</th>
                  <th className="py-3.5 px-5 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-800/60 text-xs">
                {filteredCases.map((c) => {
                  const verdict = (c.verdict || c.risk?.verdict || 'SAFE').toUpperCase();
                  const isMalicious = verdict.includes('MALICIOUS');
                  const isSuspicious = verdict.includes('SUSPICIOUS');
                  const score = c.risk?.score ?? (typeof c.score === 'number' ? c.score : 0);
                  const isDlp = c.dlp_security?.masking_active !== false && c.dlp_masking !== false;
                  const isCurrentLoading = loadingCaseId === c.case_id;
                  const isCurrentDownloading = downloadingCaseId === c.case_id;

                  return (
                    <tr
                      key={c.case_id}
                      onClick={() => handleRowClick(c.case_id)}
                      className="hover:bg-zinc-900/70 transition-colors cursor-pointer group"
                    >
                      {/* Case ID */}
                      <td className="py-4 px-5">
                        <div className="flex items-center gap-1.5">
                          <span className="font-mono text-cyan-400 font-bold tracking-wide group-hover:text-cyan-300">
                            {c.case_id}
                          </span>
                          <button
                            onClick={(e) => handleCopy(e, c.case_id)}
                            className="p-1 rounded hover:bg-zinc-800 text-zinc-600 hover:text-cyan-400 opacity-0 group-hover:opacity-100 transition-opacity"
                            title="Copy Case ID"
                          >
                            {copiedId === c.case_id ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                          </button>
                        </div>
                      </td>

                      {/* Timestamp */}
                      <td className="py-4 px-4 text-zinc-400 font-mono text-[11px] whitespace-nowrap">
                        {formatDate(c.created_at || c.date)}
                      </td>

                      {/* Sender & Subject */}
                      <td className="py-4 px-4 max-w-xs">
                        <div className="font-bold text-slate-100 truncate group-hover:text-white">
                          {c.subject || '(No Subject)'}
                        </div>
                        <div className="text-[11px] font-mono text-zinc-400 truncate mt-0.5">
                          {c.sender_display_name ? `${c.sender_display_name} <${c.sender_address || c.sender}>` : (c.sender || 'Unknown Sender')}
                        </div>
                      </td>

                      {/* Risk Score */}
                      <td className="py-4 px-4 text-center">
                        <div className="inline-flex items-center justify-center font-black text-sm px-2.5 py-1 rounded-md bg-zinc-950 border border-zinc-800">
                          <span className={isMalicious ? 'text-rose-500' : isSuspicious ? 'text-amber-400' : 'text-emerald-400'}>
                            {score}
                          </span>
                          <span className="text-[9px] text-zinc-600 ml-1">/100</span>
                        </div>
                      </td>

                      {/* Threat Verdict (Color-coded: Red for MALICIOUS, Yellow for SUSPICIOUS, Green for SAFE) */}
                      <td className="py-4 px-4">
                        <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-[10px] font-bold uppercase tracking-wider border ${
                          isMalicious
                            ? 'bg-rose-500/10 text-rose-500 border-rose-500/30'
                            : isSuspicious
                            ? 'bg-amber-500/10 text-amber-400 border-amber-500/30'
                            : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                        }`}>
                          {isMalicious ? (
                            <AlertTriangle className="w-3 h-3 text-rose-500 shrink-0" />
                          ) : isSuspicious ? (
                            <AlertCircle className="w-3 h-3 text-amber-400 shrink-0" />
                          ) : (
                            <CheckCircle2 className="w-3 h-3 text-emerald-400 shrink-0" />
                          )}
                          <span>{verdict}</span>
                        </span>
                      </td>

                      {/* DLP Status Badge (Masked / Unmasked) */}
                      <td className="py-4 px-4">
                        <span className={`inline-flex items-center gap-1 px-2.5 py-1 rounded-md text-[10px] font-bold uppercase tracking-wider border ${
                          isDlp
                            ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                            : 'bg-rose-500/10 text-rose-400 border-rose-500/30'
                        }`}>
                          {isDlp ? <ShieldCheck className="w-3 h-3 shrink-0" /> : <ShieldAlert className="w-3 h-3 shrink-0" />}
                          <span>{isDlp ? 'Masked' : 'Unmasked'}</span>
                        </span>
                      </td>

                      {/* Actions */}
                      <td className="py-4 px-5 text-right">
                        <div className="inline-flex items-center gap-2">
                          <button
                            onClick={(e) => handleDownloadPdf(e, c.case_id)}
                            disabled={isCurrentDownloading}
                            className="p-1.5 rounded-lg bg-zinc-950 border border-zinc-800 hover:border-cyan-500/50 hover:bg-cyan-950/20 text-zinc-400 hover:text-cyan-300 transition-colors"
                            title="Download Certified PDF Report"
                          >
                            {isCurrentDownloading ? <Loader2 className="w-3.5 h-3.5 animate-spin text-cyan-400" /> : <Download className="w-3.5 h-3.5" />}
                          </button>
                          
                          <button
                            onClick={() => handleRowClick(c.case_id)}
                            disabled={isCurrentLoading}
                            className="flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-zinc-950 border border-zinc-800 hover:border-cyan-500/50 hover:bg-zinc-900 text-zinc-300 hover:text-cyan-400 text-[10px] font-bold uppercase tracking-wider transition-colors"
                          >
                            {isCurrentLoading ? (
                              <Loader2 className="w-3 h-3 animate-spin text-cyan-400" />
                            ) : (
                              <>
                                <span>Inspect</span>
                                <ArrowRight className="w-3 h-3 group-hover:translate-x-0.5 transition-transform" />
                              </>
                            )}
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          {/* MOBILE RESPONSIVE CARDS */}
          <div className="md:hidden flex flex-col gap-3">
            {filteredCases.map((c) => {
              const verdict = (c.verdict || c.risk?.verdict || 'SAFE').toUpperCase();
              const isMalicious = verdict.includes('MALICIOUS');
              const isSuspicious = verdict.includes('SUSPICIOUS');
              const score = c.risk?.score ?? (typeof c.score === 'number' ? c.score : 0);
              const isDlp = c.dlp_security?.masking_active !== false && c.dlp_masking !== false;
              const isCurrentLoading = loadingCaseId === c.case_id;
              const isCurrentDownloading = downloadingCaseId === c.case_id;

              return (
                <div
                  key={c.case_id}
                  onClick={() => handleRowClick(c.case_id)}
                  className="bg-[#0f111a] backdrop-blur-xl border border-slate-700/80 rounded-2xl p-4 shadow-lg flex flex-col gap-3 active:scale-[0.99] transition-transform"
                >
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-xs font-bold text-cyan-400">{c.case_id}</span>
                    <div className="flex items-center gap-1.5">
                      <span className={`px-2 py-0.5 rounded text-[9px] font-bold uppercase border ${
                        isMalicious
                          ? 'bg-rose-500/10 text-rose-500 border-rose-500/30'
                          : isSuspicious
                          ? 'bg-amber-500/10 text-amber-400 border-amber-500/30'
                          : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                      }`}>
                        {verdict}
                      </span>
                      <span className={`px-2 py-0.5 rounded text-[9px] font-bold uppercase border ${
                        isDlp ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30' : 'bg-rose-500/10 text-rose-400 border-rose-500/30'
                      }`}>
                        {isDlp ? 'Masked' : 'Unmasked'}
                      </span>
                    </div>
                  </div>

                  <div>
                    <h4 className="font-bold text-slate-100 text-sm line-clamp-1">{c.subject || '(No Subject)'}</h4>
                    <p className="text-zinc-400 font-mono text-[11px] truncate mt-0.5">{c.sender || 'Unknown Sender'}</p>
                  </div>

                  <div className="flex items-center justify-between pt-2 border-t border-zinc-800/80 text-[11px]">
                    <div className="flex items-center gap-2">
                      <span className="text-zinc-500 font-mono">{formatDate(c.created_at || c.date)}</span>
                      <span className="text-zinc-600">•</span>
                      <span className={`font-bold ${isMalicious ? 'text-rose-500' : isSuspicious ? 'text-amber-400' : 'text-emerald-400'}`}>
                        Risk: {score}/100
                      </span>
                    </div>

                    <div className="flex items-center gap-2">
                      <button
                        onClick={(e) => handleDownloadPdf(e, c.case_id)}
                        disabled={isCurrentDownloading}
                        className="p-1.5 rounded-lg bg-zinc-950 border border-zinc-800 text-zinc-400 hover:text-cyan-300"
                      >
                        {isCurrentDownloading ? <Loader2 className="w-3.5 h-3.5 animate-spin text-cyan-400" /> : <Download className="w-3.5 h-3.5" />}
                      </button>
                      <button
                        onClick={() => handleRowClick(c.case_id)}
                        className="flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-cyan-950/40 border border-cyan-500/40 text-cyan-400 text-[10px] font-bold uppercase tracking-wider"
                      >
                        {isCurrentLoading ? <Loader2 className="w-3 h-3 animate-spin" /> : <span>Open</span>}
                      </button>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </>
      )}

    </div>
  );
}
