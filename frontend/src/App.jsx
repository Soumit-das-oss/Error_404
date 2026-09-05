import { useState } from 'react';
import { AlertCircle, X } from 'lucide-react';
import VajraBackground from './components/VajraBackground';
import Header from './components/Header';
import UploadState from './components/UploadState';
import ScanningLoader from './components/ScanningLoader';
import TechnicalView from './components/TechnicalView';
import SimpleView from './components/SimpleView';
import AboutView from './components/AboutView';

export default function App() {
  const [activeTab, setActiveTab] = useState('desktop'); 
  const [scanData, setScanData] = useState(null);
  const [isScanning, setIsScanning] = useState(false);
  const [error, setError] = useState(null);

  const handleScan = async (payload) => {
    setIsScanning(true);
    setError(null);
    setScanData(null);
    
    await new Promise(resolve => setTimeout(resolve, 3500));

    try {
      const response = await fetch('http://localhost:8000/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type: payload.type, data: "..." }) 
      });
      
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      
      const data = await response.json();
      setScanData(data);
    } catch (err) {
      console.error(err);
      setError("Connection Refused: Target backend [localhost:8000] is offline.");
    } finally {
      setIsScanning(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#050507] text-white font-sans selection:bg-amber-500/30 overflow-x-hidden relative">
      <VajraBackground />
      
      {/* Error Toast Banner */}
      {error && (
        <div className="fixed top-6 left-1/2 -translate-x-1/2 z-50 animate-in slide-in-from-top-4 fade-in duration-300 w-[90%] max-w-lg">
          <div className="bg-rose-950/90 border border-rose-500/50 rounded-xl p-4 shadow-[0_0_30px_rgba(244,63,94,0.3)] backdrop-blur-md flex items-start gap-3">
            <AlertCircle className="w-5 h-5 text-rose-500 shrink-0 mt-0.5" />
            <div className="flex-1">
              <h4 className="text-rose-500 font-bold text-sm tracking-wide">SYSTEM FAILURE</h4>
              <p className="text-zinc-300 text-xs font-mono mt-1">{error}</p>
            </div>
            <button onClick={() => setError(null)} className="text-zinc-400 hover:text-white transition-colors">
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>
      )}

      <div className="relative z-10 flex flex-col min-h-screen">
        <Header activeTab={activeTab} setActiveTab={setActiveTab} />

        <main className="flex-1 w-full max-w-7xl mx-auto p-6 flex flex-col">
          <div key={activeTab} className="flex-1 flex flex-col animate-in fade-in duration-500">
            {activeTab === 'about' && !scanData && !isScanning && (
              <AboutView />
            )}

            {activeTab !== 'about' && !scanData && !isScanning && (
              <UploadState activeTab={activeTab} onScan={handleScan} />
            )}

            {isScanning && (
              <ScanningLoader />
            )}

            {scanData && !isScanning && (
              <div className="w-full h-full flex-1 mt-4 sm:mt-0">
                {activeTab === 'desktop' ? (
                  <TechnicalView data={scanData} />
                ) : (
                  <SimpleView data={scanData} />
                )}
              </div>
            )}
          </div>
        </main>
      </div>
    </div>
  );
}
