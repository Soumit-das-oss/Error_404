import { useState, useRef } from 'react';
import { UploadCloud, FileText, Scan, FileImage, X, CheckCircle2, Shield } from 'lucide-react';

export default function UploadState({ activeTab, onScan }) {
  const [selectedFile, setSelectedFile] = useState(null);
  const [textContent, setTextContent] = useState("");
  const [dragActive, setDragActive] = useState(false);
  const fileInputRef = useRef(null);

  const handleDrag = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === "dragenter" || e.type === "dragover") setDragActive(true);
    else if (e.type === "dragleave") setDragActive(false);
  };

  const validateAndSetFile = (file) => {
    if (file && (file.name.endsWith('.eml') || file.name.endsWith('.msg') || file.name.endsWith('.txt'))) {
      setSelectedFile(file);
    } else {
      alert("Invalid file type. Please upload .eml, .msg, or .txt files.");
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) validateAndSetFile(e.dataTransfer.files[0]);
  };

  const handleChange = (e) => {
    e.preventDefault();
    if (e.target.files && e.target.files[0]) validateAndSetFile(e.target.files[0]);
  };

  const handleScanClick = () => {
    if (activeTab === 'desktop' && selectedFile) {
      onScan({ type: 'file', data: selectedFile });
    } else if (activeTab === 'mobile' && textContent.trim()) {
      onScan({ type: 'text', data: textContent });
    }
  };

  const isScanDisabled = (activeTab === 'desktop' && !selectedFile) || (activeTab === 'mobile' && !textContent.trim());

  return (
    <div className="w-full max-w-2xl mx-auto flex flex-col gap-6 animate-in fade-in slide-in-from-bottom-4 duration-500 my-auto py-4">
      
      <div className="flex flex-col gap-4">
        {activeTab === 'desktop' ? (
          /* Desktop: Thick Premium Frosted Glass Dropzone */
          <div 
            onDragEnter={handleDrag} onDragLeave={handleDrag} onDragOver={handleDrag} onDrop={handleDrop}
            onClick={() => !selectedFile && fileInputRef.current?.click()}
            className={`bg-[#0f111a] backdrop-blur-xl border border-dashed rounded-2xl shadow-[0_0_20px_rgba(0,0,0,0.8)] flex flex-col items-center justify-center text-center cursor-pointer transition-colors duration-300 h-40 relative ${
              dragActive 
                ? 'border-cyan-500 bg-[#161925]' 
                : 'border-slate-700 hover:border-cyan-500/50 hover:bg-[#161925]'
            }`}
          >
            <input ref={fileInputRef} type="file" className="hidden" accept=".eml,.msg,.txt" onChange={handleChange} />
            
            {selectedFile ? (
              <div className="flex items-center gap-4 animate-in zoom-in duration-300 px-6">
                <div className="w-12 h-12 bg-cyan-500/10 border border-cyan-500/30 rounded-full flex items-center justify-center shadow-[0_0_15px_rgba(34,211,238,0.2)] shrink-0">
                  <FileText className="w-6 h-6 text-cyan-400" />
                </div>
                <div className="text-left overflow-hidden flex-1">
                  <h3 className="text-sm sm:text-base text-cyan-400 font-bold truncate">{selectedFile.name}</h3>
                  <p className="text-[10px] sm:text-xs text-cyan-500/70">{(selectedFile.size / 1024).toFixed(2)} KB • Ready</p>
                </div>
                <button 
                  onClick={(e) => { e.stopPropagation(); setSelectedFile(null); }}
                  className="p-1.5 rounded-full bg-zinc-900 hover:bg-rose-500/20 hover:text-rose-400 text-zinc-500 transition-colors shrink-0"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>
            ) : (
              <div className="flex flex-col items-center group pointer-events-none">
                <div className="mb-2">
                  <UploadCloud className="w-8 h-8 text-cyan-400 group-hover:scale-110 transition-transform drop-shadow-[0_0_8px_rgba(34,211,238,0.5)]" />
                </div>
                <h3 className="text-sm font-bold tracking-wide text-slate-100">Drag & Drop .eml File</h3>
                <p className="text-[10px] text-zinc-500 mt-1">Click to browse or drop file here</p>
              </div>
            )}
          </div>
        ) : (
          /* Mobile: Thick Premium Frosted Glass Text Area */
          <div className="flex flex-col gap-3">
            <div className="bg-[#0f111a] backdrop-blur-xl border border-slate-700 rounded-2xl shadow-[0_0_20px_rgba(0,0,0,0.8)] flex flex-col overflow-hidden focus-within:border-cyan-500/50 hover:border-cyan-500/50 hover:bg-[#161925] transition-colors duration-300">
              <div className="bg-transparent px-3 py-2 border-b border-zinc-800/40 flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <FileText className="w-3 h-3 text-zinc-400" />
                  <span className="text-[9px] font-bold uppercase tracking-widest text-zinc-400">Raw Content</span>
                </div>
                {textContent && (
                   <button onClick={() => setTextContent('')} className="text-zinc-500 hover:text-rose-400 transition-colors"><X className="w-3.5 h-3.5"/></button>
                )}
              </div>
              <textarea 
                value={textContent}
                onChange={(e) => setTextContent(e.target.value)}
                className="w-full bg-transparent p-3 text-sm font-mono text-slate-100 resize-none outline-none custom-scrollbar h-32"
                placeholder="Paste raw email headers or body..."
              ></textarea>
            </div>
            
            {/* Scan Capability Indicators */}
            <div className="text-slate-400 text-xs font-mono flex gap-4 justify-center mt-3">
              <div className="flex items-center gap-1.5"><CheckCircle2 className="w-3.5 h-3.5 text-cyan-500/70" /> Header Analysis</div>
              <div className="flex items-center gap-1.5"><Shield className="w-3.5 h-3.5 text-cyan-500/70" /> NLP Intent Check</div>
              <div className="flex items-center gap-1.5"><Scan className="w-3.5 h-3.5 text-cyan-500/70" /> Payload Extraction</div>
            </div>

            <label className="flex items-center justify-center gap-2 bg-[#0f111a] backdrop-blur-xl border border-slate-700 rounded-2xl shadow-[0_0_20px_rgba(0,0,0,0.8)] hover:border-cyan-500/50 hover:bg-[#161925] py-2 text-sm text-slate-100 hover:text-white transition-colors duration-300 group cursor-pointer mt-2">
              <input type="file" className="hidden" accept=".pdf, image/*" onChange={(e) => {
                if (e.target.files && e.target.files[0]) setSelectedFile(e.target.files[0]);
              }} />
              <FileImage className="w-4 h-4 text-cyan-400" />
              <span className="font-bold tracking-wider truncate px-2">{selectedFile ? selectedFile.name : "Attach the files if presented in email"}</span>
            </label>
          </div>
        )}
      </div>

      <button 
        onClick={handleScanClick}
        disabled={isScanDisabled}
        className={`mx-auto flex items-center justify-center gap-2 font-black tracking-widest uppercase px-6 py-2.5 rounded-lg transition-all w-full sm:w-auto text-xs ${
          isScanDisabled 
            ? 'bg-zinc-900/50 text-zinc-600 cursor-not-allowed border border-zinc-800/50' 
            : 'bg-gradient-to-r from-cyan-950 to-slate-900 border border-cyan-500/50 text-cyan-400 hover:shadow-[0_0_20px_rgba(34,211,238,0.2)] hover:scale-105'
        }`}
      >
        <Scan className="w-4 h-4 shrink-0" />
        Initiate Scan
      </button>
    </div>
  );
}
