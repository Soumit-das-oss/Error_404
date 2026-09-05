import { useState, useEffect } from 'react';
import { ScanSearch } from 'lucide-react';

const terminalSteps = [
  "Initializing Cyber-Forensic Engine...",
  "Parsing RFC-822 Headers...",
  "Extracting IP Routing Matrix...",
  "Validating Cryptographic Signatures (DKIM/SPF)...",
  "Running Heuristic NLP Vision Models...",
  "Cross-referencing Global Threat Intelligence...",
  "Compiling Final Risk Assessment..."
];

export default function ScanningLoader() {
  const [stepIndex, setStepIndex] = useState(0);

  useEffect(() => {
    const interval = setInterval(() => {
      setStepIndex(prev => (prev < terminalSteps.length - 1 ? prev + 1 : prev));
    }, 800);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="flex-1 flex flex-col items-center justify-center min-h-[60vh] animate-in fade-in duration-500 my-auto">
      <div className="relative w-32 h-32 flex items-center justify-center">
        <div className="absolute inset-0 rounded-full border-t-2 border-r-2 border-cyan-500 animate-spin blur-[2px]"></div>
        <div className="absolute inset-2 rounded-full border-b-2 border-l-2 border-violet-500 animate-[spin_2s_reverse_infinite]"></div>
        <div className="absolute inset-6 rounded-full bg-zinc-900 border border-zinc-700 flex items-center justify-center shadow-[0_0_30px_rgba(6,182,212,0.2)]">
          <ScanSearch className="w-8 h-8 text-cyan-400 animate-pulse" />
        </div>
      </div>
      
      <div className="mt-8 flex flex-col items-center gap-3 text-center px-4">
        <h3 className="text-xl font-bold text-zinc-200 tracking-wider drop-shadow-md">Analyzing Payload...</h3>
        <p className="text-[10px] sm:text-xs text-cyan-400 uppercase tracking-widest font-mono min-h-[20px] transition-all">
          {'>'} {terminalSteps[stepIndex]}
        </p>
      </div>
    </div>
  );
}
