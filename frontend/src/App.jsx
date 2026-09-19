import { useState, useEffect } from 'react';
import { AlertCircle, X, Monitor, Smartphone, PlusCircle, ArrowLeft } from 'lucide-react';
import VajraBackground from './components/VajraBackground';
import Header from './components/Header';
import UploadState from './components/UploadState';
import ScanningLoader from './components/ScanningLoader';
import TechnicalView from './components/TechnicalView';
import SimpleView from './components/SimpleView';
import AboutView from './components/AboutView';
import Dashboard from './components/Dashboard';
import HeroIntro from './components/HeroIntro';
import { normalizeScanData } from './utils/normalizeScanData';

export default function App() {
  const [introFinished, setIntroFinished] = useState(false);
  const [activeTab, setActiveTab] = useState('desktop'); // Default to Intake / Upload screen on fresh load / refresh
  const [reportMode, setReportMode] = useState('technical'); // 'technical' | 'simple'
  const [scanData, setScanData] = useState(null);
  const [isScanning, setIsScanning] = useState(false);
  const [error, setError] = useState(null);

  // Strict Zero-Retention: Clean up volatile client state on window unload / refresh
  useEffect(() => {
    const handleBeforeUnload = () => {
      setScanData(null);
      setError(null);
    };
    window.addEventListener('beforeunload', handleBeforeUnload);
    return () => {
      window.removeEventListener('beforeunload', handleBeforeUnload);
    };
  }, []);

  const handleScan = async (payload) => {
    setIsScanning(true);
    setError(null);

    const isDesktop = payload.type === 'desktop' || payload.type === 'file';
    const dlpParam = payload.dlpMasking !== false ? 'true' : 'false';

    // Desktop targets /api/v1/upload (file upload), Mobile targets /api/v1/raw (raw email)
    const targetUrl = isDesktop
      ? `http://localhost:8000/api/v1/upload?dlp_masking=${dlpParam}`
      : `http://localhost:8000/api/v1/raw?dlp_masking=${dlpParam}`;

    // Smooth animation timer for scanner experience
    const minDelayPromise = new Promise((resolve) => setTimeout(resolve, 2600));

    try {
      const formData = new FormData();

      if (isDesktop) {
        // Desktop upload: multipart file (.eml / .msg)
        formData.append('file', payload.data);
      } else {
        // Mobile upload: RFC 5322 raw email text with optional attachments
        formData.append('raw_email', payload.data);
        if (Array.isArray(payload.attachments) && payload.attachments.length > 0) {
          payload.attachments.forEach((att) => {
            formData.append('attachments', att);
          });
        } else if (payload.attachment) {
          formData.append('attachments', payload.attachment);
        }
      }

      const response = await fetch(targetUrl, {
        method: 'POST',
        body: formData,
      });

      if (!response.ok) {
        let errMsg = `Forensic Engine returned HTTP ${response.status}`;
        try {
          const errJson = await response.json();
          errMsg = errJson.error?.message || errJson.detail || errMsg;
        } catch {
          // ignore json parse failure
        }
        throw new Error(errMsg);
      }

      const rawData = await response.json();
      const normalized = normalizeScanData(rawData);

      await minDelayPromise;
      setScanData(normalized);
      setReportMode(isDesktop ? 'technical' : 'simple');
      setActiveTab('report');
    } catch (err) {
      console.error('Forensic Scan Failure:', err);
      setError(err.message || 'Target forensic backend [localhost:8000] is unavailable.');
    } finally {
      setIsScanning(false);
    }
  };

  const handleSelectCase = async (caseId) => {
    setError(null);
    try {
      const cleanId = String(caseId).trim();
      const res = await fetch(`http://localhost:8000/api/v1/cases/${encodeURIComponent(cleanId)}`);
      if (!res.ok) {
        throw new Error(`Failed to load forensic case ${cleanId} (HTTP ${res.status})`);
      }
      const rawData = await res.json();
      const normalized = normalizeScanData(rawData);
      setScanData(normalized);
      setActiveTab('report');
    } catch (err) {
      console.error('Error opening case:', err);
      setError(err.message || `Failed to fetch case ${caseId}`);
    }
  };

  const handleBackToDashboard = () => {
    setActiveTab('dashboard');
  };

  const handleNewScan = () => {
    setActiveTab('desktop');
  };

  return (
    <>
      {!introFinished && <HeroIntro onComplete={() => setIntroFinished(true)} />}
      <div className="min-h-screen bg-[#050507] text-white font-sans selection:bg-cyan-500/30 overflow-x-hidden relative">
        <VajraBackground />

        {/* Error Toast Banner */}
        {error && (
          <div className="fixed top-6 left-1/2 -translate-x-1/2 z-50 animate-in slide-in-from-top-4 fade-in duration-300 w-[90%] max-w-lg">
            <div className="bg-rose-950/95 border border-rose-500/60 rounded-xl p-4 shadow-[0_0_30px_rgba(244,63,94,0.35)] backdrop-blur-md flex items-start gap-3">
              <AlertCircle className="w-5 h-5 text-rose-500 shrink-0 mt-0.5" />
              <div className="flex-1">
                <h4 className="text-rose-400 font-bold text-sm tracking-wide">SYSTEM ALERT</h4>
                <p className="text-zinc-300 text-xs font-mono mt-1 leading-relaxed">{error}</p>
              </div>
              <button onClick={() => setError(null)} className="text-zinc-400 hover:text-white transition-colors p-1">
                <X className="w-4 h-4" />
              </button>
            </div>
          </div>
        )}

        <div className="relative z-10 flex flex-col min-h-screen">
          <Header
            activeTab={activeTab}
            setActiveTab={setActiveTab}
            hasActiveReport={Boolean(scanData)}
            onViewReport={() => setActiveTab('report')}
          />

          <main className="flex-1 w-full max-w-7xl mx-auto p-4 sm:p-6 flex flex-col">
            {isScanning ? (
              <ScanningLoader />
            ) : (
              <div key={activeTab} className="flex-1 flex flex-col animate-in fade-in duration-300">
                {/* 1. SOC DASHBOARD */}
                {activeTab === 'dashboard' && (
                  <Dashboard
                    onSelectCase={handleSelectCase}
                    onNewScan={handleNewScan}
                    onWipeComplete={() => {
                      setScanData(null);
                      setActiveTab('desktop');
                    }}
                  />
                )}

                {/* 2. INGESTION VIEWS */}
                {(activeTab === 'desktop' || activeTab === 'mobile') && (
                  <UploadState activeTab={activeTab} onScan={handleScan} />
                )}

                {/* 3. ABOUT VIEW */}
                {activeTab === 'about' && (
                  <AboutView />
                )}

                {/* 4. FORENSIC REPORT DOSSIER VIEW */}
                {activeTab === 'report' && scanData && (
                  <div className="w-full flex flex-col gap-4">
                    {/* View Switcher Bar (Technical vs Simple) */}
                    <div className="flex items-center justify-between gap-3 bg-[#0f111a] backdrop-blur-xl border border-zinc-800/80 rounded-xl p-2.5 px-4 shadow-lg">
                      <div className="flex items-center gap-2">
                        <button
                          onClick={handleBackToDashboard}
                          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-zinc-950 hover:bg-zinc-900 border border-zinc-800 hover:border-zinc-700 text-zinc-300 hover:text-white text-xs font-bold uppercase tracking-wider transition-colors"
                        >
                          <ArrowLeft className="w-3.5 h-3.5" />
                          <span>SOC Cases</span>
                        </button>
                        <button
                          onClick={handleNewScan}
                          className="hidden sm:flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-zinc-950 hover:bg-zinc-900 border border-zinc-800 hover:border-cyan-500/40 text-cyan-400 text-xs font-bold uppercase tracking-wider transition-colors"
                        >
                          <PlusCircle className="w-3.5 h-3.5" />
                          <span>New Ingest</span>
                        </button>
                      </div>

                      {/* Perspective Switcher */}
                      <div className="flex items-center bg-zinc-950 p-1 rounded-lg border border-zinc-800">
                        <button
                          onClick={() => setReportMode('technical')}
                          className={`px-3 py-1 rounded-md text-[10px] sm:text-xs font-bold uppercase tracking-wider transition-all flex items-center gap-1.5 ${
                            reportMode === 'technical'
                              ? 'bg-zinc-900 text-cyan-400 border border-cyan-500/40 shadow-[0_0_10px_rgba(34,211,238,0.15)]'
                              : 'text-zinc-500 hover:text-zinc-300'
                          }`}
                        >
                          <Monitor className="w-3.5 h-3.5" />
                          <span>Technical (Analyst)</span>
                        </button>
                        <button
                          onClick={() => setReportMode('simple')}
                          className={`px-3 py-1 rounded-md text-[10px] sm:text-xs font-bold uppercase tracking-wider transition-all flex items-center gap-1.5 ${
                            reportMode === 'simple'
                              ? 'bg-zinc-900 text-cyan-400 border border-cyan-500/40 shadow-[0_0_10px_rgba(34,211,238,0.15)]'
                              : 'text-zinc-500 hover:text-zinc-300'
                          }`}
                        >
                          <Smartphone className="w-3.5 h-3.5" />
                          <span>Simple (Executive)</span>
                        </button>
                      </div>
                    </div>

                    {/* Report Content */}
                    {reportMode === 'technical' ? (
                      <TechnicalView
                        data={scanData}
                        onBack={handleBackToDashboard}
                      />
                    ) : (
                      <SimpleView
                        data={scanData}
                        onBack={handleBackToDashboard}
                      />
                    )}
                  </div>
                )}
              </div>
            )}
          </main>
        </div>
      </div>
    </>
  );
}
