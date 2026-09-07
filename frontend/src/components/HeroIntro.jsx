import React, { useState, useEffect } from 'react';
import VajraBackground from './VajraBackground';

const HeroIntro = ({ onComplete }) => {
  const [stage, setStage] = useState(0);

  useEffect(() => {
    // 0.0s - 1.8s: 3-piece triangular shield assembly (stage 0)
    const t1 = setTimeout(() => setStage(1), 1800); // 1.8s: Mid-point Thunderbolt flash and lock
    const t2 = setTimeout(() => setStage(2), 2200); // 2.2s: "VAJRA" brand text appears
    const t3 = setTimeout(() => setStage(3), 3300); // 3.3s: "DETECT."
    const t4 = setTimeout(() => setStage(4), 3700); // 3.7s: "ANALYZE."
    const t5 = setTimeout(() => setStage(5), 4100); // 4.1s: "NEUTRALIZE."
    const t6 = setTimeout(() => setStage(6), 6500); // 6.5s: Thunderbolt Exit Transition starts
    const t7 = setTimeout(() => {
      if (onComplete) onComplete();
    }, 7000); // 7.0s: Instantly unmount and slam-reveal dashboard

    return () => {
      clearTimeout(t1);
      clearTimeout(t2);
      clearTimeout(t3);
      clearTimeout(t4);
      clearTimeout(t5);
      clearTimeout(t6);
      clearTimeout(t7);
    };
  }, [onComplete]);

  // Handle ESC key for skip
  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.key === 'Escape' && onComplete) onComplete();
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [onComplete]);

  return (
    <>
      <style>{`
        @keyframes coreIgnite {
          0% { transform: scaleY(0) scaleX(0.01); opacity: 0; filter: brightness(3); }
          20% { transform: scaleY(1) scaleX(0.05); opacity: 1; filter: brightness(2); }
          100% { transform: scaleY(1) scaleX(1); opacity: 1; filter: brightness(1); }
        }
        @keyframes wingSweep {
          0% { transform: scaleX(0) scaleY(0.95); opacity: 0; filter: brightness(1.5); }
          10% { opacity: 1; }
          100% { transform: scaleX(1) scaleY(1); opacity: 1; filter: brightness(1); }
        }
        @keyframes outlinePulse {
          0% { transform: scale(1); opacity: 0.8; stroke-width: 2px; }
          100% { transform: scale(1.4); opacity: 0; stroke-width: 0.5px; }
        }
        @keyframes thunderFlash {
          0% { opacity: 0; }
          10% { opacity: 0.8; filter: brightness(2); }
          20% { opacity: 0; }
          30% { opacity: 1; filter: brightness(1.5); }
          100% { opacity: 0; }
        }
        @keyframes screenBurst {
          0% { opacity: 0; }
          10% { opacity: 1; }
          100% { opacity: 0; }
        }
        @keyframes fadeUpText {
          0% { opacity: 0; transform: translateY(20px); filter: blur(4px); }
          100% { opacity: 1; transform: translateY(0); filter: blur(0); }
        }
        @keyframes fadeInWord {
          0% { opacity: 0; transform: translateY(10px); }
          100% { opacity: 1; transform: translateY(0); }
        }
        
        .anim-core { transform-origin: 50% 50%; animation: coreIgnite 0.6s cubic-bezier(0.1, 1, 0.2, 1) forwards; }
        .anim-wing-left { transform-origin: 42% 50%; opacity: 0; animation: wingSweep 0.6s cubic-bezier(0.1, 1, 0.2, 1) 0.6s forwards; }
        .anim-wing-right { transform-origin: 58% 50%; opacity: 0; animation: wingSweep 0.6s cubic-bezier(0.1, 1, 0.2, 1) 0.6s forwards; }
        .anim-pulse { transform-origin: 50% 50%; opacity: 0; animation: outlinePulse 0.6s ease-out 1.2s forwards; }
        
        .anim-thunder-bolt { animation: thunderFlash 0.4s ease-out forwards; }
        .anim-screen-burst { animation: screenBurst 0.4s ease-out forwards; }
        
        .anim-fade-up-text { animation: fadeUpText 1s cubic-bezier(0.2, 1, 0.3, 1) forwards; }
        .anim-fade-word { animation: fadeInWord 0.5s cubic-bezier(0.2, 1, 0.3, 1) forwards; }
        
      `}</style>

      <div className={`fixed inset-0 z-50 flex flex-col items-center justify-center bg-[#050507] overflow-hidden transition-opacity duration-700 ease-in-out ${
        stage >= 6 ? 'opacity-0 pointer-events-none' : 'opacity-100'
      }`}>
        <VajraBackground />

        <button
          onClick={onComplete}
          className="absolute top-6 right-6 z-50 text-xs font-mono text-slate-500 hover:text-cyan-400 transition-colors cursor-pointer"
        >
          SKIP [ESC]
        </button>

        {/* 1.8s - 2.2s Side Thunderbolts (Less power, matching particle colors) */}
        {stage === 1 && (
          <div className="absolute inset-0 z-20 pointer-events-none flex justify-between px-4 sm:px-12">
            {/* Left Lightning Array */}
            <svg viewBox="0 0 50 100" preserveAspectRatio="none" className="w-[10%] sm:w-[5%] h-full opacity-0 anim-thunder-bolt">
              <path d="M 25,0 L 45,25 L 15,40 L 50,60 L 20,80 L 35,100" fill="none" stroke="#8a2be2" strokeWidth="1.5" className="drop-shadow-[0_0_5px_#8a2be2]" />
              <path d="M 10,10 L 30,35 L 5,50 L 35,75 L 10,95" fill="none" stroke="#00f0ff" strokeWidth="1" className="drop-shadow-[0_0_5px_#00f0ff]" opacity="0.8" />
            </svg>
            {/* Right Lightning Array */}
            <svg viewBox="0 0 50 100" preserveAspectRatio="none" className="w-[10%] sm:w-[5%] h-full opacity-0 anim-thunder-bolt" style={{ transform: 'scaleX(-1)' }}>
              <path d="M 30,0 L 10,20 L 40,45 L 5,65 L 45,85 L 20,100" fill="none" stroke="#00f0ff" strokeWidth="1.5" className="drop-shadow-[0_0_5px_#00f0ff]" />
              <path d="M 45,15 L 20,30 L 50,55 L 15,80 L 40,90" fill="none" stroke="#8a2be2" strokeWidth="1" className="drop-shadow-[0_0_5px_#8a2be2]" opacity="0.8" />
            </svg>
          </div>
        )}

        <div 
          className="relative z-30 flex flex-col items-center w-full max-w-2xl mx-auto"
          style={{
            transform: stage >= 6 ? 'scale3d(4, 4, 4)' : 'scale3d(1, 1, 1)',
            transition: 'transform 0.6s cubic-bezier(0.4, 0, 0.2, 1), opacity 0.6s ease-out',
            opacity: stage >= 6 ? 0 : 1,
            willChange: 'transform, opacity'
          }}
        >
          {/* Triangular Vector Shield Assembly */}
          <div className="relative flex items-center justify-center mb-6">
            <div className="relative w-36 h-36 drop-shadow-[0_0_20px_rgba(0,240,255,0.7)]">
              <svg viewBox="0 0 100 100" className="w-full h-full overflow-visible">
                {/* Outline Pulse (Phase 3) */}
                <path
                  className="anim-pulse text-cyan-400"
                  d="M 50 10 L 88 25 L 58 75 L 50 90 L 42 75 L 12 25 Z"
                  stroke="currentColor"
                  fill="none"
                  strokeWidth="2"
                  strokeLinejoin="round"
                />
                {/* Left Triangular Wing (Phase 2) */}
                <path
                  className="anim-wing-left text-cyan-400 fill-cyan-950/30"
                  d="M 12 25 L 42 25 L 42 75 Z"
                  stroke="currentColor"
                  strokeWidth="2"
                  strokeLinejoin="round"
                />
                {/* Right Triangular Wing (Phase 2) */}
                <path
                  className="anim-wing-right text-cyan-400 fill-cyan-950/30"
                  d="M 88 25 L 58 25 L 58 75 Z"
                  stroke="currentColor"
                  strokeWidth="2"
                  strokeLinejoin="round"
                />
                {/* Center Core Spear (Phase 1) */}
                <path
                  className="anim-core text-cyan-400 fill-cyan-950/30"
                  d="M 50 10 L 65 35 L 50 90 L 35 35 Z"
                  stroke="currentColor"
                  strokeWidth="2"
                  strokeLinejoin="round"
                />
              </svg>
            </div>
          </div>

          {/* Massive Brand Name */}
          <div className="h-24 flex items-center justify-center w-full text-center">
            {stage >= 2 && (
              <h1 className="font-mono text-6xl md:text-7xl font-black tracking-[0.3em] pl-[0.3em] text-cyan-300 drop-shadow-[0_0_20px_rgba(0,240,255,0.5)] anim-fade-up-text">
                VAJRA
              </h1>
            )}
          </div>

          {/* Staggered Tagline */}
          <div className="h-10 mt-6 flex items-center justify-center space-x-6 md:space-x-8 font-mono text-sm md:text-base font-semibold tracking-[0.25em] text-cyan-400">
            {stage >= 3 && <span className="anim-fade-word">DETECT.</span>}
            {stage >= 4 && <span className="anim-fade-word">ANALYZE.</span>}
            {stage >= 5 && <span className="anim-fade-word">NEUTRALIZE.</span>}
          </div>
        </div>
      </div>
    </>
  );
};

export default HeroIntro;
