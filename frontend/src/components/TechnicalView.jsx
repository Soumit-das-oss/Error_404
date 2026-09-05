import { AlertTriangle, Shield, KeyRound, Lock, Terminal, Globe, Network, Code2, ArrowRight, Ban, Share2, Download, CheckCircle2, XCircle } from 'lucide-react';

const RiskGauge = ({ score }) => {
  const radius = 40;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (score / 100) * circumference;

  return (
    <div className="w-32 h-32 sm:w-44 sm:h-44 mx-auto relative flex items-center justify-center">
      <svg className="w-full h-full transform -rotate-90" viewBox="0 0 100 100">
        <circle cx="50" cy="50" r={radius} fill="transparent" stroke="rgba(244, 63, 94, 0.2)" strokeWidth="8" />
        <circle
          cx="50" cy="50" r={radius} fill="transparent" stroke="#f43f5e" strokeWidth="8"
          strokeDasharray={circumference} strokeDashoffset={strokeDashoffset} strokeLinecap="round"
          className="drop-shadow-[0_0_8px_rgba(244,63,94,0.6)] transition-all duration-1000 ease-out"
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-3xl sm:text-4xl font-black text-rose-500 drop-shadow-md">{score}</span>
        <span className="text-[9px] sm:text-[10px] font-bold text-zinc-400 uppercase tracking-widest mt-0.5 sm:mt-1">Risk</span>
      </div>
    </div>
  );
};

function AuthCard({ title, icon, data }) {
  const isPass = data.pass;
  const themeClass = isPass 
    ? 'border-emerald-500/30 bg-emerald-500/5 hover:border-emerald-500/50' 
    : 'border-rose-500/30 bg-rose-500/5 hover:border-rose-500/50';
  const iconClass = isPass ? 'text-emerald-500 bg-emerald-500/10' : 'text-rose-500 bg-rose-500/10';
  const badgeClass = isPass ? 'border-emerald-500/30 text-emerald-500 bg-emerald-500/10' : 'border-rose-500/30 text-rose-500 bg-rose-500/10';

  return (
    <div className={`rounded-xl border p-4 sm:p-5 transition-colors duration-300 bg-zinc-900/80 backdrop-blur-sm shadow-lg flex flex-col gap-3 ${themeClass}`}>
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <div className={`p-1.5 rounded-lg ${iconClass}`}>{icon}</div>
          <span className="font-bold text-zinc-200 text-sm sm:text-base">{title}</span>
        </div>
        <div className={`flex items-center gap-1 sm:gap-1.5 px-2 py-1 sm:px-2.5 sm:py-1 rounded-md border text-[9px] sm:text-[10px] font-bold uppercase tracking-wider ${badgeClass}`}>
          {isPass ? <CheckCircle2 className="w-3 h-3 sm:w-3.5 sm:h-3.5" /> : <XCircle className="w-3 h-3 sm:w-3.5 sm:h-3.5" />}
          {isPass ? 'Pass' : 'Fail'}
        </div>
      </div>
      <p className="text-[11px] sm:text-xs text-zinc-400 font-medium leading-relaxed mt-1">{data.detail}</p>
    </div>
  );
}

export default function TechnicalView({ data }) {
  return (
    <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 sm:gap-6 w-full animate-in fade-in duration-500 pb-10">
      
      {/* LEFT COLUMN */}
      <div className="lg:col-span-4 flex flex-col gap-4 sm:gap-6">
        
        {/* Risk Score Card */}
        <div className="bg-zinc-900/80 backdrop-blur-sm border border-zinc-800 rounded-xl p-5 sm:p-6 shadow-xl hover:border-rose-500/40 transition-colors duration-300 flex flex-col items-center">
          <RiskGauge score={data.score} />
          
          <div className="mt-4 sm:mt-6 flex flex-col items-center text-center">
            <div className="flex items-center gap-1.5 sm:gap-2 bg-rose-500/10 border border-rose-500/20 px-3 sm:px-4 py-1.5 sm:py-2 rounded-full mb-2">
              <AlertTriangle className="w-3.5 h-3.5 sm:w-4 sm:h-4 text-rose-500" />
              <span className="text-rose-500 font-bold text-xs sm:text-sm tracking-wide">{data.status}</span>
            </div>
            <p className="text-zinc-400 text-[11px] sm:text-xs font-medium px-2">{data.subStatus}</p>
          </div>

          <div className="grid grid-cols-3 gap-2 sm:gap-3 w-full mt-6 sm:mt-8">
            <button className="flex flex-col items-center justify-center gap-1.5 p-2 sm:p-3 rounded-lg bg-zinc-950 border border-zinc-800 hover:border-rose-500/50 hover:bg-rose-500/10 text-zinc-400 hover:text-rose-400 transition-colors group">
              <Ban className="w-3.5 h-3.5 sm:w-4 sm:h-4 group-hover:scale-110 transition-transform" />
              <span className="text-[9px] sm:text-[10px] font-bold uppercase tracking-wider">Block</span>
            </button>
            <button className="flex flex-col items-center justify-center gap-1.5 p-2 sm:p-3 rounded-lg bg-zinc-950 border border-zinc-800 hover:border-zinc-500/50 hover:bg-zinc-800 text-zinc-400 hover:text-zinc-200 transition-colors group">
              <Download className="w-3.5 h-3.5 sm:w-4 sm:h-4 group-hover:scale-110 transition-transform" />
              <span className="text-[9px] sm:text-[10px] font-bold uppercase tracking-wider">Export</span>
            </button>
            <button className="flex flex-col items-center justify-center gap-1.5 p-2 sm:p-3 rounded-lg bg-zinc-950 border border-zinc-800 hover:border-amber-500/50 hover:bg-amber-500/10 text-zinc-400 hover:text-amber-400 transition-colors group">
              <Share2 className="w-3.5 h-3.5 sm:w-4 sm:h-4 group-hover:scale-110 transition-transform" />
              <span className="text-[9px] sm:text-[10px] font-bold uppercase tracking-wider">Escalate</span>
            </button>
          </div>
        </div>

        {/* Threat Indicators */}
        <div className="bg-zinc-900/80 backdrop-blur-sm border border-zinc-800 rounded-xl p-5 sm:p-6 shadow-xl hover:border-cyan-500/40 transition-colors duration-300">
          <h3 className="text-[11px] sm:text-xs font-bold uppercase tracking-widest text-zinc-500 mb-3 sm:mb-4 flex items-center gap-2">
            <Network className="w-3.5 h-3.5 sm:w-4 sm:h-4 text-zinc-400" /> Attack Vectors
          </h3>
          <div className="flex flex-col gap-2 sm:gap-3">
            {data.indicators.map((ind, idx) => (
              <div key={idx} className="flex items-center justify-between p-2.5 sm:p-3 rounded bg-zinc-950 border border-zinc-800/50">
                <span className="text-xs sm:text-sm text-zinc-300 font-medium truncate pr-2">{ind.label}</span>
                <div className={`px-2 py-1 rounded text-[9px] sm:text-[10px] font-bold uppercase tracking-wider shrink-0 ${
                  ind.type === 'rose' 
                    ? 'bg-rose-500/10 text-rose-500 border border-rose-500/20' 
                    : 'bg-amber-500/10 text-amber-500 border border-amber-500/20'
                }`}>
                  {ind.type === 'rose' ? 'Critical' : 'High'}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* RIGHT COLUMN */}
      <div className="lg:col-span-8 flex flex-col gap-4 sm:gap-6">
        
        {/* Auth Matrix */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 sm:gap-4">
          <AuthCard title="SPF" icon={<Shield className="w-3.5 h-3.5 sm:w-4 sm:h-4" />} data={data.auth.spf} />
          <AuthCard title="DKIM" icon={<KeyRound className="w-3.5 h-3.5 sm:w-4 sm:h-4" />} data={data.auth.dkim} />
          <AuthCard title="DMARC" icon={<Lock className="w-3.5 h-3.5 sm:w-4 sm:h-4" />} data={data.auth.dmarc} />
        </div>

        {/* NLP Forensic Assessment */}
        <div className="bg-zinc-900/80 backdrop-blur-sm border border-zinc-800 rounded-xl p-5 sm:p-6 shadow-xl hover:border-cyan-500/40 transition-colors duration-300 flex flex-col gap-3 sm:gap-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between border-b border-zinc-800 pb-3 sm:pb-4 gap-3 sm:gap-0">
            <h3 className="text-[11px] sm:text-xs font-bold uppercase tracking-widest text-zinc-500 flex items-center gap-2">
              <Terminal className="w-3.5 h-3.5 sm:w-4 sm:h-4 text-zinc-400" /> NLP Assessment
            </h3>
            
            <div className="flex items-center gap-2 px-2.5 py-1.5 sm:px-3 sm:py-1.5 rounded-full bg-zinc-950 border border-zinc-800 w-fit">
              <Globe className={`w-3 h-3 sm:w-3.5 sm:h-3.5 ${data.nlp.isTor ? 'text-rose-500' : 'text-zinc-400'}`} />
              <span className="font-mono text-[11px] sm:text-xs text-zinc-300">{data.nlp.ip}</span>
              {data.nlp.isTor && (
                <span className="text-[9px] sm:text-[10px] font-bold text-rose-500 uppercase tracking-widest border-l border-zinc-800 pl-2 ml-1">
                  Tor Exit
                </span>
              )}
            </div>
          </div>
          <p className="text-xs sm:text-sm text-zinc-300 leading-relaxed font-medium">
            {data.nlp.verdict}
          </p>
        </div>

        {/* Trace Map & Headers */}
        <div className="bg-zinc-900/80 backdrop-blur-sm border border-zinc-800 rounded-xl shadow-xl overflow-hidden hover:border-cyan-500/40 transition-colors duration-300 flex flex-col">
          
          <div className="p-4 sm:p-6 border-b border-zinc-800 flex flex-col gap-4 sm:gap-6">
            <h3 className="text-[11px] sm:text-xs font-bold uppercase tracking-widest text-zinc-500 flex items-center gap-2">
              <Network className="w-3.5 h-3.5 sm:w-4 sm:h-4 text-zinc-400" /> Routing Hops
            </h3>
            
            {/* Native horizontal scrolling on all devices for Trace Nodes */}
            <div className="flex flex-row items-center gap-3 sm:gap-4 overflow-x-auto pb-4 snap-x">
              {data.trace.map((node, idx) => (
                <div key={idx} className="flex items-center gap-3 sm:gap-4 shrink-0 snap-start">
                  <div className={`flex flex-col gap-2 p-2.5 sm:p-3 rounded-lg border bg-zinc-950 w-[130px] sm:w-[140px] shrink-0 ${
                    node.type === 'danger' ? 'border-rose-500/30' :
                    node.type === 'warn' ? 'border-amber-500/30' :
                    'border-emerald-500/30'
                  }`}>
                    <div className="flex items-center justify-between">
                      <span className="text-[9px] sm:text-[10px] font-bold text-zinc-400 uppercase tracking-wider">{node.geo}</span>
                      <div className={`w-1.5 h-1.5 sm:w-2 sm:h-2 rounded-full ${
                        node.type === 'danger' ? 'bg-rose-500 shadow-[0_0_8px_rgba(244,63,94,0.8)]' :
                        node.type === 'warn' ? 'bg-amber-500 shadow-[0_0_8px_rgba(245,158,11,0.8)]' :
                        'bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.8)]'
                      }`} />
                    </div>
                    <span className="text-[11px] sm:text-xs font-bold text-zinc-200 truncate">{node.label}</span>
                    <span className="font-mono text-[9px] sm:text-[10px] text-cyan-400 truncate w-full block">{node.ip}</span>
                  </div>
                  
                  {idx < data.trace.length - 1 && (
                    <ArrowRight className="w-3.5 h-3.5 sm:w-4 sm:h-4 text-zinc-600 shrink-0" />
                  )}
                </div>
              ))}
            </div>
          </div>

          <div className="p-4 sm:p-6 bg-[#090b13] flex flex-col gap-2 sm:gap-3">
            <h3 className="text-[9px] sm:text-[10px] font-bold uppercase tracking-widest text-zinc-500 flex items-center gap-2">
              <Code2 className="w-3 h-3 sm:w-3.5 sm:h-3.5 text-zinc-400" /> Raw Headers Inspector
            </h3>
            <div className="overflow-auto max-h-[120px] sm:max-h-[150px] custom-scrollbar">
              <pre className="font-mono text-[10px] sm:text-[11px] text-zinc-400 leading-relaxed whitespace-pre-wrap break-all pr-2">
                {data.headers}
              </pre>
            </div>
          </div>

        </div>

      </div>
    </div>
  );
}
