import { Shield, Ban } from 'lucide-react';

export default function SimpleView({ data }) {
  const isDanger = data.score > 50;

  return (
    <div className="w-full max-w-2xl mx-auto flex flex-col gap-4 sm:gap-6 animate-in fade-in slide-in-from-bottom-4 duration-500 mt-6 sm:mt-12">
      
      {/* Big Status Banner */}
      <div className={`${isDanger ? 'bg-rose-500/10 border-rose-500/30 shadow-[0_0_30px_rgba(244,63,94,0.1)] hover:border-rose-500/50' : 'bg-emerald-500/10 border-emerald-500/30 shadow-[0_0_30px_rgba(16,185,129,0.1)] hover:border-emerald-500/50'} border rounded-2xl p-6 sm:p-8 flex flex-col items-center text-center transition-colors`}>
        <div className={`w-16 h-16 sm:w-20 sm:h-20 rounded-full flex items-center justify-center mb-4 sm:mb-6 ${isDanger ? 'bg-rose-500/20 text-rose-500' : 'bg-emerald-500/20 text-emerald-500'}`}>
          <Shield className="w-8 h-8 sm:w-10 sm:h-10" />
          {isDanger && (
            <div className="absolute">
              <Ban className="w-10 h-10 sm:w-12 sm:h-12 opacity-50 stroke-1" />
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

      {/* Action */}
      {isDanger ? (
        <button className="w-full bg-rose-600 hover:bg-rose-500 text-white font-bold py-3.5 sm:py-4 rounded-xl shadow-[0_0_20px_rgba(244,63,94,0.3)] transition-all flex items-center justify-center gap-2 sm:gap-3 group text-xs sm:text-base">
          <Ban className="w-4 h-4 sm:w-5 sm:h-5 group-hover:scale-110 transition-transform shrink-0" />
          QUARANTINE & DELETE EMAIL
        </button>
      ) : (
        <button className="w-full bg-zinc-800 hover:bg-zinc-700 text-white font-bold py-3.5 sm:py-4 rounded-xl transition-all flex items-center justify-center gap-2 sm:gap-3 text-xs sm:text-base">
          MARK AS READ
        </button>
      )}
      
    </div>
  );
}
