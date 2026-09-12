import { useEffect, useState } from 'react';
import {
  ScanLine,
  FileCode2,
  KeyRound,
  Database,
  Link2,
  Route,
  ShieldAlert,
  Gauge,
  CheckCircle2,
} from 'lucide-react';

// Time each stage stays "active" before the next one appears (ms)
const STEP_MS = 1000;

const STAGES = [
  {
    key: 'scan',
    title: 'Document Scanning',
    desc: 'Reading raw email structure & headers',
    icon: ScanLine,
  },
  {
    key: 'parsing',
    title: 'Parsing',
    desc: 'Extracting headers, body & attachments',
    icon: FileCode2,
  },
  {
    key: 'authentication',
    title: 'Authentication',
    desc: 'Verifying SPF, DKIM & DMARC records',
    icon: KeyRound,
  },
  {
    key: 'metadata',
    title: 'Metadata',
    desc: 'Inspecting sender & routing metadata',
    icon: Database,
  },
  {
    key: 'url',
    title: 'URL Analysis',
    desc: 'Scanning embedded links for intent',
    icon: Link2,
  },
  {
    key: 'trace',
    title: 'Geo Trace',
    desc: 'Tracing IP hops & delivery path',
    icon: Route,
  },
  {
    key: 'threat',
    title: 'Threat Detection',
    desc: 'Matching indicators against intel feeds',
    icon: ShieldAlert,
  },
  {
    key: 'risk',
    title: 'Risk Scoring',
    desc: 'Calculating composite forensic score',
    icon: Gauge,
  },
];

export default function ScanningLoader() {
  const [currentIndex, setCurrentIndex] = useState(0);
  const [finished, setFinished] = useState(false);

  // Reveal stages one by one; once the last one has had its turn, settle
  // into a "finished" state and let the footer loading text take over
  // (it just holds there if the real scan takes longer than the animation).
  useEffect(() => {
    if (currentIndex < STAGES.length - 1) {
      const t = setTimeout(() => setCurrentIndex((i) => i + 1), STEP_MS);
      return () => clearTimeout(t);
    }
    if (!finished) {
      const t = setTimeout(() => setFinished(true), STEP_MS);
      return () => clearTimeout(t);
    }
  }, [currentIndex, finished]);

  // Lock page scroll while this full-screen overlay is up, and reset scroll
  // position back to top when it unmounts, so whatever renders next (the
  // results view) starts lined up with the header.
  useEffect(() => {
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    return () => {
      document.body.style.overflow = previousOverflow;
      window.scrollTo(0, 0);
    };
  }, []);

  return (
    <div
      className="fixed inset-x-0 top-0 h-dvh z-[9999] bg-[#050507] flex flex-col items-center justify-center px-4 sm:px-6 md:px-10 py-10 md:py-16 overflow-y-auto"
      role="status"
      aria-live="polite"
    >
      <div className="w-full max-w-3xl md:max-w-4xl lg:max-w-5xl xl:max-w-6xl">
        {/* Header */}
        <div className="flex items-center gap-3 md:gap-4 mb-8 md:mb-10 pb-6 md:pb-8 border-b border-zinc-800/60">
          <div className="relative w-11 h-11 md:w-14 md:h-14 shrink-0 rounded-full bg-zinc-950 border border-amber-500/30 flex items-center justify-center overflow-hidden shadow-[0_0_20px_rgba(245,158,11,0.25)]">
            <img
              src="/vajra.png"
              alt="Vajra Symbol"
              className="h-8 md:h-10 w-auto object-contain mix-blend-screen drop-shadow-[0_0_8px_rgba(245,158,11,0.6)] animate-[spin_5s_linear_infinite]"
            />
          </div>
          <div>
            <h3 className="text-sm sm:text-base md:text-lg font-black tracking-widest text-zinc-100 uppercase">
              Analyzing Transmission
            </h3>
            <p className="text-[10px] md:text-xs text-amber-400/80 font-mono uppercase tracking-widest mt-0.5">
              Vajra Forensic Engine
            </p>
          </div>
        </div>

        {/* 8-stage vertical stepper */}
        <div className="flex flex-col">
          {STAGES.slice(0, currentIndex + 1).map((stage, i) => {
            const Icon = stage.icon;
            const isDone = i < currentIndex || (i === currentIndex && finished);
            const isActive = i === currentIndex && !finished;
            const isLastRendered = i === currentIndex;

            return (
              <div key={stage.key} className="flex gap-4 md:gap-6 stage-row-enter">
                {/* Icon rail */}
                <div className="flex flex-col items-center">
                  <div className="relative w-11 h-11 md:w-14 md:h-14 shrink-0">
                    {isActive && (
                      <>
                        <span className="absolute inset-0 rounded-full bg-amber-500/15 animate-ping" />
                        <span className="absolute inset-0 rounded-full border-2 border-amber-400/70 border-t-transparent animate-spin" />
                      </>
                    )}
                    <div
                      className={`absolute inset-[3px] rounded-full flex items-center justify-center border backdrop-blur-sm transition-colors duration-300 ${isDone
                        ? 'bg-emerald-500/10 border-emerald-500/40'
                        : 'bg-amber-500/10 border-amber-500/40'
                        }`}
                    >
                      {isDone ? (
                        <CheckCircle2 className="w-5 h-5 md:w-6 md:h-6 text-emerald-400 stage-check-pop" />
                      ) : (
                        <Icon className="w-5 h-5 md:w-6 md:h-6 text-amber-400" />
                      )}
                    </div>
                  </div>

                  {/* Connector line down to the next stage */}
                  {!isLastRendered && (
                    <div
                      className={`w-px flex-1 my-1 stage-line-grow ${i < currentIndex ? 'bg-emerald-500/40' : 'bg-zinc-800'
                        }`}
                    />
                  )}
                </div>

                {/* Text */}
                <div className={`flex-1 flex items-start justify-between gap-2 ${isLastRendered ? 'pb-1' : 'pb-6 md:pb-8'}`}>
                  <div>
                    <h4
                      className={`text-sm md:text-base font-bold tracking-wide ${isDone ? 'text-zinc-300' : 'text-zinc-100'
                        }`}
                    >
                      {stage.title}
                    </h4>
                    <p className="text-xs md:text-sm text-zinc-500 mt-0.5 md:mt-1">{stage.desc}</p>
                  </div>
                  <span
                    className={`text-[9px] md:text-[10px] font-bold uppercase tracking-widest shrink-0 mt-1 md:mt-1.5 ${isDone
                      ? 'text-emerald-500'
                      : isActive
                        ? 'text-amber-400 animate-pulse'
                        : 'text-zinc-600'
                      }`}
                  >
                    {isDone ? 'Done' : isActive ? 'Scanning' : ''}
                  </span>
                </div>
              </div>
            );
          })}
        </div>

        {/* Final "loading" text once all 8 stages have appeared */}
        {finished && (
          <div className="stage-row-enter flex items-center gap-3 pt-4 md:pt-6 mt-1 border-t border-zinc-800/60">
            <div className="flex gap-1">
              <span className="loading-dot w-1.5 h-1.5 md:w-2 md:h-2 rounded-full bg-amber-400" style={{ animationDelay: '0s' }} />
              <span className="loading-dot w-1.5 h-1.5 md:w-2 md:h-2 rounded-full bg-amber-400" style={{ animationDelay: '0.2s' }} />
              <span className="loading-dot w-1.5 h-1.5 md:w-2 md:h-2 rounded-full bg-amber-400" style={{ animationDelay: '0.4s' }} />
            </div>
            <span className="text-xs md:text-sm font-mono uppercase tracking-widest text-amber-400/90">
              Compiling Forensic Report...
            </span>
          </div>
        )}
      </div>
    </div>
  );
}