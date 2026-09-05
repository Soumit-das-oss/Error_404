import { Shield, Monitor, Smartphone, Info } from 'lucide-react';

export default function Header({ activeTab, setActiveTab }) {
  return (
    <header className="flex-none px-4 sm:px-6 py-3 sm:py-4 bg-[#050507]/80 backdrop-blur-md border-b border-zinc-800/50 shadow-lg z-50">
      <div className="max-w-7xl mx-auto flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 sm:w-9 sm:h-9 rounded bg-zinc-950 border border-zinc-800/50 flex items-center justify-center shadow-[0_0_15px_rgba(34,211,238,0.15)] shrink-0">
            <Shield className="w-4 h-4 sm:w-5 sm:h-5 text-cyan-400" strokeWidth={2} />
          </div>
          <div>
            <h1 className="text-lg sm:text-xl font-black tracking-widest text-white leading-none">VAJRA</h1>
            <p className="text-[9px] sm:text-[10px] uppercase tracking-widest text-zinc-500 font-bold mt-1 leading-none">Forensic Intelligence</p>
          </div>
        </div>

        {/* TAB SWITCHER */}
        <div className="flex p-1 bg-zinc-950 border border-zinc-800/50 rounded-lg w-full sm:w-auto shadow-[0_4px_20px_rgba(0,0,0,0.5)]">
          <button
            onClick={() => setActiveTab('about')}
            className={`flex-1 sm:flex-none px-2 sm:px-4 py-2 rounded-md text-[10px] sm:text-xs font-bold uppercase tracking-wider transition-all duration-500 flex items-center justify-center gap-1.5 sm:gap-2 ${
              activeTab === 'about' 
                ? 'bg-zinc-900 text-cyan-400 shadow-[0_0_15px_rgba(34,211,238,0.15)] border border-cyan-500/50' 
                : 'text-zinc-500 hover:text-cyan-200 hover:bg-zinc-900/60'
            }`}
          >
            <Info className="w-3 sm:w-3.5 h-3 sm:h-3.5 shrink-0" />
            <span className="truncate">About</span>
          </button>
          <button
            onClick={() => setActiveTab('desktop')}
            className={`flex-1 sm:flex-none px-2 sm:px-4 py-2 rounded-md text-[10px] sm:text-xs font-bold uppercase tracking-wider transition-all duration-500 flex items-center justify-center gap-1.5 sm:gap-2 ${
              activeTab === 'desktop' 
                ? 'bg-zinc-900 text-cyan-400 shadow-[0_0_15px_rgba(34,211,238,0.15)] border border-cyan-500/50' 
                : 'text-zinc-500 hover:text-cyan-200 hover:bg-zinc-900/60'
            }`}
          >
            <Monitor className="w-3 sm:w-3.5 h-3 sm:h-3.5 shrink-0" />
            <span className="truncate">Desktop</span>
          </button>
          <button
            onClick={() => setActiveTab('mobile')}
            className={`flex-1 sm:flex-none px-2 sm:px-4 py-2 rounded-md text-[10px] sm:text-xs font-bold uppercase tracking-wider transition-all duration-500 flex items-center justify-center gap-1.5 sm:gap-2 ${
              activeTab === 'mobile' 
                ? 'bg-zinc-900 text-cyan-400 shadow-[0_0_15px_rgba(34,211,238,0.15)] border border-cyan-500/50' 
                : 'text-zinc-500 hover:text-cyan-200 hover:bg-zinc-900/60'
            }`}
          >
            <Smartphone className="w-3 sm:w-3.5 h-3 sm:h-3.5 shrink-0" />
            <span className="truncate">Mobile</span>
          </button>
        </div>
      </div>
    </header>
  );
}
