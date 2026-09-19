import { useState } from 'react';
import { Globe, ShieldCheck, ArrowRight, X } from 'lucide-react';

/**
 * Check if IP is RFC 1918 Private, Loopback, or Link-Local
 */
function isPrivateOrLoopbackIp(ip) {
  if (!ip || typeof ip !== 'string') return true;
  const cleanIp = ip.trim();
  if (
    cleanIp === '127.0.0.1' ||
    cleanIp === '::1' ||
    cleanIp === 'localhost' ||
    cleanIp.startsWith('10.') ||
    cleanIp.startsWith('192.168.') ||
    cleanIp.startsWith('169.254.')
  ) {
    return true;
  }
  if (cleanIp.startsWith('172.')) {
    const parts = cleanIp.split('.');
    const octet2 = parseInt(parts[1], 10);
    if (!isNaN(octet2) && octet2 >= 16 && octet2 <= 31) return true;
  }
  return false;
}

/**
 * Equirectangular Coordinate Projection Math:
 * x = (Number(lon) + 180) * (viewBoxWidth / 360)
 * y = (90 - Number(lat)) * (viewBoxHeight / 180)
 */
function projectCoords(lat, lon, width = 1000, height = 500) {
  const x = (Number(lon) + 180) * (width / 360);
  const y = (90 - Number(lat)) * (height / 180);
  return {
    x: Math.max(30, Math.min(width - 30, x)),
    y: Math.max(30, Math.min(height - 85, y)),
  };
}

export default function HopTransitMap({ hops = [], trace = [] }) {
  const [hoveredHop, setHoveredHop] = useState(null);
  const [selectedHop, setSelectedHop] = useState(null);
  const [viewMode, setViewMode] = useState('map'); // 'map' | 'rail'

  // Normalize hops from either CaseResponseDTO.hops or fallback trace
  const sourceList = Array.isArray(hops) && hops.length > 0 
    ? hops 
    : (Array.isArray(trace) && trace.length > 0 ? trace : []);

  const normalizedHops = sourceList.map((h, idx) => {
    const hopNumber = h.hop_number || idx + 1;
    const ip = h.ip || 'Unknown IP';
    const isPrivate = isPrivateOrLoopbackIp(ip);
    
    // Check latitude and longitude
    const lat = h.latitude !== undefined && h.latitude !== null ? Number(h.latitude) : null;
    const lon = h.longitude !== undefined && h.longitude !== null ? Number(h.longitude) : null;
    const hasGeo = lat !== null && lon !== null && !isNaN(lat) && !isNaN(lon);

    const isTor = Boolean(h.is_tor_exit || h.type === 'danger');
    const isDatacenter = Boolean(h.is_datacenter || h.type === 'warn');
    const isHighDelay = h.delay_seconds !== undefined && h.delay_seconds !== null && Number(h.delay_seconds) > 15;

    let country = h.country || h.country_code || (hasGeo ? 'Global' : 'PRIVATE');
    if (!country && h.geo) country = h.geo;

    return {
      raw: h,
      hopNumber,
      ip,
      hostname: h.hostname || (h.label && !h.label.startsWith('Hop') ? h.label : 'None reported'),
      city: h.city || (hasGeo ? 'MTA Hub' : 'Enclave Intranet'),
      country,
      countryCode: h.country_code || (hasGeo ? 'INTL' : 'LOC'),
      lat,
      lon,
      hasGeo,
      isPrivate,
      isOrigin: idx === 0 || hopNumber === 1,
      isTor,
      isDatacenter,
      isHighDelay,
      delay: h.delay_seconds !== undefined && h.delay_seconds !== null
        ? `+${Number(h.delay_seconds).toFixed(2)}s`
        : (idx === 0 ? '0.00s (Origin)' : 'Undetected'),
      asnOrg: h.asn_org || (h.asn ? `AS${h.asn}` : null),
    };
  });

  const hasAnyGeo = normalizedHops.some((h) => h.hasGeo);
  const totalPrivate = normalizedHops.filter((h) => !h.hasGeo).length;
  const geoCount = normalizedHops.filter((h) => h.hasGeo).length;

  // Active inspected hop (hover or pinned)
  const activeHop = hoveredHop || selectedHop;

  // 1000x500 Equirectangular SVG Viewport
  const viewBoxWidth = 1000;
  const viewBoxHeight = 500;

  // 1. Unified Coordinate Assignment (Strict Chronological Indexing)
  const railY = viewBoxHeight - 40;
  const railStartX = 140;
  const railSpacing = totalPrivate > 1 
    ? Math.min(180, (viewBoxWidth - 280) / (totalPrivate - 1)) 
    : 0;

  const hopsWithCoords = normalizedHops.map((hop, index) => {
    let coords;
    if (hop.hasGeo) {
      coords = projectCoords(hop.lat, hop.lon, viewBoxWidth, viewBoxHeight);
    } else {
      const privateSlotIndex = normalizedHops.slice(0, index).filter((h) => !h.hasGeo).length;
      const x = totalPrivate === 1 ? 220 : railStartX + privateSlotIndex * railSpacing;
      coords = { x, y: railY };
    }
    return {
      ...hop,
      coords,
    };
  });

  return (
    <div className="bg-[#0f111a] backdrop-blur-xl border border-zinc-800 rounded-2xl shadow-[0_0_25px_rgba(0,0,0,0.8)] overflow-hidden flex flex-col">
      
      {/* MAP HEADER BAR */}
      <div className="p-4 sm:p-5 border-b border-zinc-800/80 flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-[#0a0c13]">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center shrink-0 shadow-[0_0_12px_rgba(34,211,238,0.2)]">
            <Globe className="w-5 h-5 text-cyan-400" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-xs sm:text-sm font-bold text-slate-100 uppercase tracking-widest flex items-center gap-1.5">
                MTA Routing Transit Map
              </h3>
              <span className="px-2 py-0.5 rounded-full text-[9px] font-bold font-mono bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
                100% AIR-GAPPED 2D SVG
              </span>
            </div>
            <p className="text-[10px] text-zinc-400 font-mono mt-0.5">
              {hasAnyGeo
                ? `Tracing ${normalizedHops.length} relay nodes (${geoCount} Geocoded • ${totalPrivate} Enclave/Private)`
                : `Air-Gapped Intranet Enclave (${normalizedHops.length} Internal Nodes)`}
            </p>
          </div>
        </div>

        {/* CONTROLS & AIR-GAP BADGE */}
        <div className="flex items-center gap-2">
          <div className="flex items-center bg-zinc-950 p-1 rounded-lg border border-zinc-800">
            <button
              type="button"
              onClick={() => setViewMode('map')}
              className={`px-2.5 py-1 rounded text-[10px] font-bold uppercase tracking-wider transition-all ${
                viewMode === 'map'
                  ? 'bg-zinc-900 text-cyan-400 border border-cyan-500/40 shadow-[0_0_10px_rgba(34,211,238,0.15)]'
                  : 'text-zinc-500 hover:text-zinc-300'
              }`}
            >
              Transit Radar
            </button>
            <button
              type="button"
              onClick={() => setViewMode('rail')}
              className={`px-2.5 py-1 rounded text-[10px] font-bold uppercase tracking-wider transition-all ${
                viewMode === 'rail'
                  ? 'bg-zinc-900 text-cyan-400 border border-cyan-500/40 shadow-[0_0_10px_rgba(34,211,238,0.15)]'
                  : 'text-zinc-500 hover:text-zinc-300'
              }`}
            >
              Hop Matrix
            </button>
          </div>
        </div>
      </div>

      {/* MAP VIEW CONTAINER */}
      <div className="relative w-full overflow-hidden bg-[#08090e] p-2 sm:p-4 select-none">
        
        {viewMode === 'map' && hasAnyGeo ? (
          /* 1. AIR-GAPPED 2D EQUIRECTANGULAR SVG WORLD MAP */
          <div className="relative w-full aspect-[2/1] min-h-[280px] max-h-[500px]">
            <svg
              viewBox={`0 0 ${viewBoxWidth} ${viewBoxHeight}`}
              className="w-full h-full drop-shadow-2xl"
              preserveAspectRatio="xMidYMid meet"
            >
              <defs>
                {/* Cyan Transit Glow Filter */}
                <filter id="cyanGlow" x="-20%" y="-20%" width="140%" height="140%">
                  <feGaussianBlur stdDeviation="3" result="blur" />
                  <feMerge>
                    <feMergeNode in="blur" />
                    <feMergeNode in="SourceGraphic" />
                  </feMerge>
                </filter>

                {/* Radar Grid Gradient */}
                <linearGradient id="gridGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                  <stop offset="0%" stopColor="rgba(34, 211, 238, 0.05)" />
                  <stop offset="100%" stopColor="rgba(15, 23, 42, 0.2)" />
                </linearGradient>
              </defs>

              {/* Background Canvas */}
              <rect width={viewBoxWidth} height={viewBoxHeight} fill="url(#gridGrad)" rx="12" />

              {/* Grid Lines (Parallels & Meridians) */}
              <g stroke="rgba(51, 65, 85, 0.3)" strokeWidth="0.8" strokeDasharray="3 3">
                {/* Equator */}
                <line x1="0" y1="250" x2={viewBoxWidth} y2="250" stroke="rgba(34, 211, 238, 0.25)" strokeWidth="1.2" />
                {/* Tropics */}
                <line x1="0" y1="185" x2={viewBoxWidth} y2="185" />
                <line x1="0" y1="315" x2={viewBoxWidth} y2="315" />
                {/* Prime Meridian */}
                <line x1="500" y1="0" x2="500" y2={viewBoxHeight} stroke="rgba(34, 211, 238, 0.25)" strokeWidth="1.2" />
                {/* Major Meridians */}
                <line x1="250" y1="0" x2="250" y2={viewBoxHeight} />
                <line x1="750" y1="0" x2="750" y2={viewBoxHeight} />
              </g>

              {/* AIR-GAPPED EQUIRECTANGULAR CONTINENT SILHOUETTES */}
              <g className="fill-slate-800/60 stroke-slate-700/50" strokeWidth="1.2">
                {/* North America */}
                <path d="M 120,60 L 150,50 L 180,55 L 210,45 L 250,55 L 280,75 L 310,85 L 290,110 L 260,115 L 285,140 L 285,170 L 260,195 L 245,190 L 215,235 L 200,215 L 185,195 L 165,165 L 135,175 L 115,135 L 110,95 Z" />
                {/* Greenland */}
                <path d="M 335,40 L 395,35 L 420,70 L 375,105 L 330,80 Z" />
                {/* South America */}
                <path d="M 270,240 L 330,235 L 380,270 L 410,310 L 380,380 L 340,450 L 315,455 L 290,380 L 270,300 L 260,260 Z" />
                {/* Europe & Scandinavia & British Isles */}
                <path d="M 455,75 L 495,65 L 540,70 L 555,110 L 530,140 L 485,145 L 460,120 L 440,95 Z" />
                <path d="M 505,45 L 545,50 L 535,100 L 510,90 Z" />
                <path d="M 445,95 L 465,90 L 460,120 L 440,115 Z" />
                {/* Africa & Madagascar */}
                <path d="M 460,175 L 535,165 L 585,200 L 610,260 L 590,320 L 550,385 L 510,385 L 480,320 L 450,230 L 450,190 Z" />
                <path d="M 618,310 L 632,315 L 622,355 L 608,345 Z" />
                {/* Asia & Subcontinents */}
                <path d="M 555,65 L 665,55 L 765,60 L 865,80 L 885,130 L 835,150 L 815,195 L 775,235 L 725,240 L 685,195 L 635,195 L 595,160 L 565,135 Z" />
                <path d="M 685,195 L 735,205 L 720,265 L 690,240 Z" />
                <path d="M 865,140 L 885,145 L 870,185 L 855,170 Z" />
                <path d="M 775,245 L 815,250 L 795,285 L 755,270 Z M 785,295 L 835,295 L 825,315 L 780,310 Z M 845,290 L 885,295 L 865,320 L 840,315 Z" />
                {/* Australia & New Zealand */}
                <path d="M 820,325 L 890,315 L 930,345 L 920,405 L 860,420 L 815,385 L 810,345 Z" />
                <path d="M 945,400 L 960,405 L 940,440 L 930,430 Z" />
              </g>

              {/* INTERNAL ENCLAVE RAIL (BOTTOM SHELF) */}
              {totalPrivate > 0 && (
                <g className="internal-rail">
                  {/* Rail Track Line */}
                  <rect 
                    x="25" 
                    y={railY - 14} 
                    width={viewBoxWidth - 50} 
                    height="28" 
                    rx="8" 
                    fill="rgba(15, 23, 42, 0.7)" 
                    stroke="rgba(51, 65, 85, 0.6)" 
                    strokeWidth="1" 
                  />
                  <text x="35" y={railY + 4} className="fill-zinc-500 font-mono text-[9px] font-bold uppercase tracking-widest">
                    RFC 1918 Enclave Rail
                  </text>
                </g>
              )}

              {/* SEQUENTIAL HOP ARCS (STRICT i -> i + 1) */}
              {hopsWithCoords.map((hop, idx) => {
                if (idx < hopsWithCoords.length - 1) {
                  const next = hopsWithCoords[idx + 1];
                  const x1 = hop.coords.x;
                  const y1 = hop.coords.y;
                  const x2 = next.coords.x;
                  const y2 = next.coords.y;
                  const midX = (x1 + x2) / 2;
                  const midY = Math.max(15, Math.min(y1, y2) - 40);
                  const isThreatPath = next.isTor || next.isHighDelay;

                  return (
                    <g key={`seq-arc-${hop.hopNumber}-${next.hopNumber}`}>
                      {/* Ambient Shadow Path */}
                      <path
                        d={`M ${x1} ${y1} Q ${midX} ${midY} ${x2} ${y2}`}
                        fill="none"
                        stroke={isThreatPath ? 'rgba(244, 63, 94, 0.3)' : 'rgba(34, 211, 238, 0.25)'}
                        strokeWidth="4"
                      />
                      {/* Active Glowing Dashed Transition Line */}
                      <path
                        d={`M ${x1} ${y1} Q ${midX} ${midY} ${x2} ${y2}`}
                        fill="none"
                        stroke={isThreatPath ? 'rgba(244, 63, 94, 0.85)' : 'rgba(34, 211, 238, 0.85)'}
                        strokeWidth="2"
                        strokeDasharray="4 2"
                        filter="url(#cyanGlow)"
                      />
                    </g>
                  );
                }
                return null;
              })}

              {/* PLOT ALL NODES (WORLD MAP & ENCLAVE RAIL) */}
              {hopsWithCoords.map((hop) => {
                const { x, y } = hop.coords;
                const isOrigin = hop.isOrigin;
                const isDanger = hop.isTor || hop.isHighDelay;
                const isSelected = activeHop?.hopNumber === hop.hopNumber;

                if (hop.hasGeo) {
                  return (
                    <g
                      key={`geo-node-${hop.hopNumber}`}
                      className="cursor-pointer transition-all duration-200"
                      onMouseEnter={() => setHoveredHop(hop)}
                      onMouseLeave={() => setHoveredHop(null)}
                      onClick={() => setSelectedHop(isSelected ? null : hop)}
                    >
                      {/* Origin Node: Pulsing Emerald Pin */}
                      {isOrigin ? (
                        <g>
                          <circle cx={x} cy={y} r="14" className="fill-emerald-500/20 stroke-emerald-400/80 stroke-[1.5] animate-ping" />
                          <circle cx={x} cy={y} r="7" className="fill-emerald-500 stroke-emerald-200 stroke-2 drop-shadow-[0_0_12px_rgba(16,185,129,0.9)]" />
                          <circle cx={x} cy={y} r="2.5" className="fill-white" />
                          <text x={x} y={y - 12} textAnchor="middle" className="fill-emerald-400 font-mono text-[9px] font-bold pointer-events-none drop-shadow">
                            Hop {hop.hopNumber} [Origin]
                          </text>
                        </g>
                      ) : isDanger ? (
                        /* Danger Node: Red Pulsing Alert Pin */
                        <g>
                          <circle cx={x} cy={y} r="12" className="fill-rose-500/25 stroke-rose-500/90 stroke-2 animate-pulse" />
                          <circle cx={x} cy={y} r="6" className="fill-rose-500 stroke-white stroke-2 drop-shadow-[0_0_12px_rgba(244,63,94,0.9)]" />
                          <text x={x} y={y - 10} textAnchor="middle" className="fill-rose-400 font-mono text-[9px] font-bold pointer-events-none drop-shadow">
                            Hop {hop.hopNumber} {hop.isTor ? '[TOR]' : ''}
                          </text>
                        </g>
                      ) : (
                        /* Standard Intermediate Relay Node */
                        <g>
                          <circle cx={x} cy={y} r="8" className="fill-sky-500/20 stroke-sky-400/70 stroke-[1.5]" />
                          <circle cx={x} cy={y} r="5" className="fill-sky-400 stroke-white stroke-1 drop-shadow-[0_0_8px_rgba(56,189,248,0.8)]" />
                          <text x={x} y={y - 10} textAnchor="middle" className="fill-sky-300 font-mono text-[9px] font-bold pointer-events-none drop-shadow">
                            Hop {hop.hopNumber}
                          </text>
                        </g>
                      )}

                      {/* Selection Ring */}
                      {isSelected && (
                        <circle cx={x} cy={y} r="16" fill="none" stroke="rgba(34, 211, 238, 0.9)" strokeWidth="1.5" strokeDasharray="2 2" />
                      )}
                    </g>
                  );
                } else {
                  /* Rail Node: Enclave Box Pin */
                  return (
                    <g
                      key={`rail-node-${hop.hopNumber}`}
                      className="cursor-pointer transition-all duration-200"
                      onMouseEnter={() => setHoveredHop(hop)}
                      onMouseLeave={() => setHoveredHop(null)}
                      onClick={() => setSelectedHop(isSelected ? null : hop)}
                    >
                      <rect
                        x={x - 8}
                        y={y - 8}
                        width="16"
                        height="16"
                        rx="3"
                        className={
                          isOrigin
                            ? "fill-emerald-500/20 stroke-emerald-400/80 stroke-[1.5]"
                            : isDanger
                            ? "fill-rose-500/20 stroke-rose-400/80 stroke-[1.5]"
                            : "fill-amber-500/20 stroke-amber-400/80 stroke-[1.5]"
                        }
                      />
                      <circle 
                        cx={x} 
                        cy={y} 
                        r="3" 
                        className={
                          isOrigin ? "fill-emerald-400" : isDanger ? "fill-rose-400" : "fill-amber-400"
                        } 
                      />
                      <text 
                        x={x} 
                        y={y - 12} 
                        textAnchor="middle" 
                        className={`font-mono text-[8px] font-bold pointer-events-none ${
                          isOrigin ? "fill-emerald-400" : isDanger ? "fill-rose-400" : "fill-amber-400"
                        }`}
                      >
                        Hop {hop.hopNumber} {isOrigin ? '[Origin]' : '[RFC 1918]'}
                      </text>

                      {isSelected && (
                        <rect x={x - 12} y={y - 12} width="24" height="24" rx="4" fill="none" stroke="rgba(245, 158, 11, 0.9)" strokeWidth="1.5" strokeDasharray="2 2" />
                      )}
                    </g>
                  );
                }
              })}
            </svg>

            {/* FLOATING GLASS TOOLTIP CARD (HOVER / SELECT) */}
            {activeHop && (
              <div className="absolute top-3 right-3 z-30 max-w-xs w-full bg-[#0f111a]/95 backdrop-blur-xl border border-cyan-500/50 rounded-xl p-3.5 shadow-[0_0_30px_rgba(0,0,0,0.9)] animate-in fade-in zoom-in-95 duration-150">
                <div className="flex items-start justify-between gap-2 border-b border-zinc-800 pb-2 mb-2">
                  <div className="flex items-center gap-2">
                    <span className="w-2 h-2 rounded-full bg-cyan-400 animate-ping" />
                    <h4 className="text-xs font-bold text-slate-100 font-mono">
                      Hop #{activeHop.hopNumber} {activeHop.isOrigin ? '• Origin MTA' : ''}
                    </h4>
                  </div>
                  <button 
                    type="button" 
                    onClick={() => { setHoveredHop(null); setSelectedHop(null); }}
                    className="text-zinc-500 hover:text-white transition-colors p-0.5"
                  >
                    <X className="w-3.5 h-3.5" />
                  </button>
                </div>

                <div className="flex flex-col gap-1.5 text-[11px] font-mono">
                  <div className="flex items-center justify-between">
                    <span className="text-zinc-500">Relay IP:</span>
                    <span className="text-cyan-300 font-bold">{activeHop.ip}</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-zinc-500">Location:</span>
                    <span className="text-slate-200 truncate max-w-[170px]">
                      {activeHop.hasGeo ? `${activeHop.city}, ${activeHop.country}` : 'Internal Enclave'}
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-zinc-500">Latency Delay:</span>
                    <span className={`font-bold ${activeHop.isHighDelay ? 'text-rose-400' : 'text-emerald-400'}`}>
                      {activeHop.delay}
                    </span>
                  </div>
                  {activeHop.hostname && activeHop.hostname !== 'None reported' && (
                    <div className="flex items-start justify-between gap-2">
                      <span className="text-zinc-500 shrink-0">Reverse DNS:</span>
                      <span className="text-zinc-300 truncate max-w-[170px]" title={activeHop.hostname}>
                        {activeHop.hostname}
                      </span>
                    </div>
                  )}
                  {activeHop.asnOrg && (
                    <div className="flex items-center justify-between">
                      <span className="text-zinc-500">ASN Org:</span>
                      <span className="text-zinc-300 truncate max-w-[170px]">{activeHop.asnOrg}</span>
                    </div>
                  )}

                  {/* Security / Threat Badges */}
                  <div className="flex items-center gap-1.5 flex-wrap pt-1 mt-1 border-t border-zinc-800/60">
                    {activeHop.isTor && (
                      <span className="px-1.5 py-0.5 rounded text-[8px] font-bold bg-rose-500/20 text-rose-400 border border-rose-500/30">
                        TOR EXIT NODE
                      </span>
                    )}
                    {activeHop.isDatacenter && (
                      <span className="px-1.5 py-0.5 rounded text-[8px] font-bold bg-amber-500/20 text-amber-400 border border-amber-500/30">
                        DATACENTER / HOSTING
                      </span>
                    )}
                    {activeHop.isPrivate && (
                      <span className="px-1.5 py-0.5 rounded text-[8px] font-bold bg-zinc-800 text-zinc-300 border border-zinc-700">
                        RFC 1918 PRIVATE
                      </span>
                    )}
                    {activeHop.isOrigin && (
                      <span className="px-1.5 py-0.5 rounded text-[8px] font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
                        PRIMARY SENDER MTA
                      </span>
                    )}
                  </div>
                </div>
              </div>
            )}
          </div>
        ) : (
          /* 2. HIGH-TECH INTERNAL AIR-GAPPED TRANSIT NETWORK TOPOLOGY VIEW (WHEN NO HOPS HAVE GEO) */
          <div className="flex flex-col gap-4 p-4 sm:p-6 bg-gradient-to-b from-[#090b13] to-[#0d101d] rounded-xl border border-zinc-800/80">
            <div className="flex items-center justify-between pb-3 border-b border-zinc-800/80">
              <div className="flex items-center gap-2">
                <ShieldCheck className="w-4 h-4 text-cyan-400" />
                <span className="text-xs font-bold uppercase tracking-widest text-slate-200">
                  Internal Air-Gapped Transit Network
                </span>
              </div>
              <span className="px-2.5 py-1 rounded-full text-[9px] font-bold font-mono bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                100% INTERNAL ENCLAVE ROUTING
              </span>
            </div>

            {/* Linear Topology Transit Pipeline */}
            <div className="flex items-center gap-3 sm:gap-4 overflow-x-auto pb-4 pt-2 custom-scrollbar">
              {normalizedHops.map((hop, idx) => (
                <div key={`topo-${hop.hopNumber}`} className="flex items-center gap-3 sm:gap-4 shrink-0">
                  <div 
                    onClick={() => setSelectedHop(hop)}
                    className={`flex flex-col gap-2 p-3 sm:p-3.5 rounded-xl border bg-[#0f111a] w-[170px] sm:w-[190px] shrink-0 transition-all cursor-pointer hover:border-cyan-500/60 shadow-lg ${
                      hop.isOrigin 
                        ? 'border-emerald-500/40 shadow-[0_0_15px_rgba(16,185,129,0.15)]' 
                        : hop.isTor 
                        ? 'border-rose-500/40 shadow-[0_0_15px_rgba(244,63,94,0.15)]' 
                        : 'border-zinc-800 hover:bg-zinc-900/60'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className="text-[10px] font-bold uppercase tracking-wider text-zinc-400 font-mono">
                        Hop #{hop.hopNumber}
                      </span>
                      <div className={`w-2 h-2 rounded-full ${
                        hop.isOrigin ? 'bg-emerald-400 animate-ping' :
                        hop.isTor ? 'bg-rose-500' : 'bg-cyan-400'
                      }`} />
                    </div>

                    <div>
                      <span className="text-xs font-bold text-slate-100 truncate block">
                        {hop.isOrigin ? 'Origin MTA Gateway' : (hop.city || 'Intranet Relay')}
                      </span>
                      <span className="font-mono text-[10px] text-cyan-400 truncate block mt-0.5">
                        {hop.ip}
                      </span>
                    </div>

                    <div className="flex items-center justify-between text-[9px] font-mono text-zinc-500 border-t border-zinc-800/60 pt-1.5 mt-0.5">
                      <span>Transit: {hop.delay}</span>
                      <span className="uppercase text-zinc-400">{hop.country}</span>
                    </div>
                  </div>

                  {idx < normalizedHops.length - 1 && (
                    <div className="flex flex-col items-center justify-center shrink-0 text-cyan-500/60">
                      <ArrowRight className="w-4 h-4" />
                      <span className="text-[8px] font-mono text-zinc-600 uppercase">MTA Link</span>
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* QUICK STATUS TICKER / GEO SUMMARY */}
      <div className="px-4 py-2.5 bg-[#0a0c13] border-t border-zinc-800/80 flex flex-wrap items-center justify-between gap-3 text-[10px] font-mono">
        <div className="flex items-center gap-3">
          <span className="text-zinc-500">MTA Chronology:</span>
          <span className="text-slate-300">
            {normalizedHops[0]?.ip || 'None'} <span className="text-cyan-400">➔</span> {normalizedHops[normalizedHops.length - 1]?.ip || 'None'}
          </span>
        </div>

        <div className="flex items-center gap-2">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
          <span className="text-zinc-400">Air-Gapped GeoIP: MaxMind MMDB Engine Validated</span>
        </div>
      </div>
    </div>
  );
}
