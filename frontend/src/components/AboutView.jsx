import { Shield, Zap, Eye } from 'lucide-react';

export default function AboutView() {
  return (
    <div className="w-full h-full flex flex-col items-center justify-center animate-in fade-in slide-in-from-bottom-4 duration-500 my-auto">
      <div className="max-w-3xl w-full mx-auto bg-zinc-950/60 backdrop-blur-xl border border-zinc-800/60 rounded-2xl p-8 shadow-[0_8px_32px_rgba(0,0,0,0.5),inset_0_1px_0_rgba(255,255,255,0.08)]">
        <h2 className="text-2xl sm:text-3xl font-black tracking-wide text-white mb-4">
          VAJRA: Next-Generation Threat Intelligence
        </h2>
        
        <p className="text-zinc-400 text-sm sm:text-base leading-relaxed mb-8">
          VAJRA is an environment-agnostic forensic tool designed to unmask sophisticated email threats, psychological manipulation, and hidden payloads. It bridges the gap between deep forensic analysis and actionable insights.
        </p>

        <div className="flex flex-col gap-5">
          <div className="flex items-start gap-4">
            <div className="p-2 rounded-lg bg-amber-500/10 border border-amber-500/20 shadow-[0_0_15px_rgba(245,158,11,0.1)]">
              <Zap className="w-5 h-5 text-amber-500" />
            </div>
            <div>
              <h3 className="text-zinc-200 font-bold tracking-wide">Multimodal Scanning</h3>
              <p className="text-xs sm:text-sm text-zinc-500 mt-1">Cross-examines attachments, QR payloads, and raw cryptographic signatures instantly.</p>
            </div>
          </div>

          <div className="flex items-start gap-4">
            <div className="p-2 rounded-lg bg-orange-500/10 border border-orange-500/20 shadow-[0_0_15px_rgba(249,115,22,0.1)]">
              <Eye className="w-5 h-5 text-orange-400" />
            </div>
            <div>
              <h3 className="text-zinc-200 font-bold tracking-wide">NLP Intent Analysis</h3>
              <p className="text-xs sm:text-sm text-zinc-500 mt-1">Detects psychological coercion, urgency manipulation, and authority spoofing.</p>
            </div>
          </div>

          <div className="flex items-start gap-4">
            <div className="p-2 rounded-lg bg-yellow-500/10 border border-yellow-500/20 shadow-[0_0_15px_rgba(234,179,8,0.1)]">
              <Shield className="w-5 h-5 text-yellow-400" />
            </div>
            <div>
              <h3 className="text-zinc-200 font-bold tracking-wide">IP Traceback</h3>
              <p className="text-xs sm:text-sm text-zinc-500 mt-1">Maps the exact routing hops to identify Tor exit nodes and malicious infrastructure.</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
