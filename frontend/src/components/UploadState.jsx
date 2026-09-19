import { useState, useRef } from 'react';
import { 
  UploadCloud, FileText, Scan, FileImage, X, CheckCircle2, 
  Shield, ShieldCheck, ShieldAlert, Plus, Paperclip, AlertTriangle 
} from 'lucide-react';

export default function UploadState({ activeTab, onScan }) {
  const [selectedFile, setSelectedFile] = useState(null);
  const [attachments, setAttachments] = useState([]);
  const [textContent, setTextContent] = useState("");
  const [dragActive, setDragActive] = useState(false);
  const [attachmentDragActive, setAttachmentDragActive] = useState(false);
  const [dlpMasking, setDlpMasking] = useState(true);
  const [showDlpWarningModal, setShowDlpWarningModal] = useState(false);
  
  const fileInputRef = useRef(null);
  const attachmentInputRef = useRef(null);

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

  // Multi-attachment handlers
  const handleAddAttachments = (fileList) => {
    if (!fileList || fileList.length === 0) return;
    const newFiles = Array.from(fileList);
    setAttachments((prev) => [...prev, ...newFiles]);
  };

  const handleRemoveAttachment = (indexToRemove) => {
    setAttachments((prev) => prev.filter((_, i) => i !== indexToRemove));
  };

  const handleAttachmentDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setAttachmentDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      handleAddAttachments(e.dataTransfer.files);
    }
  };

  const handleAttachmentDrag = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === "dragenter" || e.type === "dragover") setAttachmentDragActive(true);
    else if (e.type === "dragleave") setAttachmentDragActive(false);
  };

  const formatFileSize = (bytes) => {
    if (!bytes && bytes !== 0) return '0 KB';
    if (bytes < 1024 * 1024) {
      return `${(bytes / 1024).toFixed(1)} KB`;
    }
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  };

  const getFileBadge = (filename) => {
    const ext = filename ? filename.split('.').pop().toLowerCase() : '';
    if (ext === 'pdf') {
      return <span className="px-1.5 py-0.5 rounded text-[8px] font-bold bg-rose-500/20 text-rose-400 border border-rose-500/30">PDF</span>;
    }
    if (['png', 'jpg', 'jpeg', 'webp', 'gif'].includes(ext)) {
      return <span className="px-1.5 py-0.5 rounded text-[8px] font-bold bg-cyan-500/20 text-cyan-400 border border-cyan-500/30">IMG</span>;
    }
    return <span className="px-1.5 py-0.5 rounded text-[8px] font-bold bg-amber-500/20 text-amber-400 border border-amber-500/30">{ext.toUpperCase() || 'FILE'}</span>;
  };

  const executeScan = () => {
    if (activeTab === 'desktop' && selectedFile) {
      onScan({ type: 'desktop', data: selectedFile, dlpMasking });
    } else if (activeTab === 'mobile' && textContent.trim()) {
      onScan({ 
        type: 'mobile', 
        data: textContent, 
        attachments: attachments,
        attachment: attachments[0] || null, 
        dlpMasking 
      });
    }
  };

  const handleScanClick = () => {
    if (isScanDisabled) return;
    
    // Intercept with OpSec Confirmation Modal if DLP Masking is toggled OFF
    if (!dlpMasking) {
      setShowDlpWarningModal(true);
      return;
    }

    executeScan();
  };

  const isScanDisabled = (activeTab === 'desktop' && !selectedFile) || (activeTab === 'mobile' && !textContent.trim());

  return (
    <div className="w-full max-w-2xl mx-auto flex flex-col gap-6 animate-in fade-in slide-in-from-bottom-4 duration-500 my-auto py-4">
      
      {/* OPSEC DLP DISABLED WARNING MODAL */}
      {showDlpWarningModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in duration-200">
          <div className="bg-[#0f111a] border border-rose-500/50 rounded-2xl p-5 sm:p-6 max-w-lg w-full shadow-[0_0_50px_rgba(244,63,94,0.3)] flex flex-col gap-4 text-left relative animate-in zoom-in-95 duration-200">
            
            <div className="flex items-start justify-between gap-3">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-xl bg-rose-500/10 border border-rose-500/30 flex items-center justify-center shrink-0">
                  <AlertTriangle className="w-5 h-5 text-rose-500" />
                </div>
                <div>
                  <h3 className="text-sm sm:text-base font-bold text-slate-100 flex items-center gap-1.5">
                    ⚠️ Operational Warning: Raw PII Ingestion
                  </h3>
                  <p className="text-[10px] font-mono uppercase tracking-wider text-rose-400 mt-0.5">
                    OpSec Protocol Alert • Compliance Risk
                  </p>
                </div>
              </div>
              <button
                type="button"
                onClick={() => setShowDlpWarningModal(false)}
                className="p-1 rounded-lg text-zinc-500 hover:text-zinc-300 transition-colors"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="bg-rose-950/30 border border-rose-500/20 rounded-xl p-3.5 flex flex-col gap-2">
              <p className="text-xs text-zinc-200 leading-relaxed font-sans">
                DLP Sanitization is currently <span className="text-rose-400 font-bold uppercase">DISABLED</span>. Raw credit card numbers, phone numbers, and identifying tokens will be passed to the reasoning engine without masking. Proceed with unredacted analysis?
              </p>
            </div>

            <div className="flex items-center justify-end gap-3 pt-2">
              <button 
                type="button"
                onClick={() => { 
                  setDlpMasking(true); 
                  setShowDlpWarningModal(false); 
                }} 
                className="px-4 py-2 rounded-xl text-xs font-bold uppercase tracking-wider bg-zinc-900 hover:bg-zinc-800 text-zinc-200 hover:text-white border border-zinc-700 transition-colors"
              >
                Cancel / Enable DLP
              </button>
              <button 
                type="button"
                onClick={() => { 
                  setShowDlpWarningModal(false); 
                  executeScan(); 
                }} 
                className="px-4 py-2 rounded-xl text-xs font-bold uppercase tracking-wider bg-rose-600 hover:bg-rose-500 text-white border border-rose-400/50 shadow-[0_0_15px_rgba(244,63,94,0.4)] transition-all"
              >
                Proceed Unmasked
              </button>
            </div>
          </div>
        </div>
      )}

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
              <div className="flex items-center gap-4 animate-in zoom-in duration-300 px-6 w-full max-w-md">
                <div className="w-12 h-12 bg-cyan-500/10 border border-cyan-500/30 rounded-full flex items-center justify-center shadow-[0_0_15px_rgba(34,211,238,0.2)] shrink-0">
                  <FileText className="w-6 h-6 text-cyan-400" />
                </div>
                <div className="text-left overflow-hidden flex-1">
                  <h3 className="text-sm sm:text-base text-cyan-400 font-bold truncate">{selectedFile.name}</h3>
                  <p className="text-[10px] sm:text-xs text-cyan-500/70 font-mono">{formatFileSize(selectedFile.size)} • Ready</p>
                </div>
                <button 
                  type="button"
                  onClick={(e) => { e.stopPropagation(); setSelectedFile(null); }}
                  className="p-1.5 rounded-full bg-zinc-900 hover:bg-rose-500/20 hover:text-rose-400 text-zinc-500 transition-colors shrink-0"
                  title="Remove file"
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
                <p className="text-[10px] text-zinc-500 mt-1">Click to browse or drop RFC 5322 email file here</p>
              </div>
            )}
          </div>
        ) : (
          /* Mobile: Thick Premium Frosted Glass Text Area with Multi-Attachment Hub */
          <div className="flex flex-col gap-3">
            <div className="bg-[#0f111a] backdrop-blur-xl border border-slate-700 rounded-2xl shadow-[0_0_20px_rgba(0,0,0,0.8)] flex flex-col overflow-hidden focus-within:border-cyan-500/50 hover:border-cyan-500/50 hover:bg-[#161925] transition-colors duration-300">
              <div className="bg-transparent px-3 py-2 border-b border-zinc-800/40 flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <FileText className="w-3 h-3 text-zinc-400" />
                  <span className="text-[9px] font-bold uppercase tracking-widest text-zinc-400">Raw RFC 5322 Content</span>
                </div>
                {textContent && (
                   <button type="button" onClick={() => setTextContent('')} className="text-zinc-500 hover:text-rose-400 transition-colors"><X className="w-3.5 h-3.5"/></button>
                )}
              </div>
              <textarea 
                value={textContent}
                onChange={(e) => setTextContent(e.target.value)}
                className="w-full bg-transparent p-3 text-sm font-mono text-slate-100 resize-none outline-none custom-scrollbar h-32"
                placeholder="Paste raw email headers and body stream..."
              ></textarea>
            </div>
            
            {/* Scan Capability Indicators */}
            <div className="text-slate-400 text-xs font-mono flex gap-4 justify-center mt-1">
              <div className="flex items-center gap-1.5"><CheckCircle2 className="w-3.5 h-3.5 text-cyan-500/70" /> Header Analysis</div>
              <div className="flex items-center gap-1.5"><Shield className="w-3.5 h-3.5 text-cyan-500/70" /> NLP Intent Check</div>
              <div className="flex items-center gap-1.5"><Scan className="w-3.5 h-3.5 text-cyan-500/70" /> Payload Extraction</div>
            </div>

            {/* Multi-Attachment Intake Hub */}
            <div className="flex flex-col gap-2 mt-1">
              <input 
                ref={attachmentInputRef}
                type="file" 
                multiple
                className="hidden" 
                accept=".pdf,image/*,.png,.jpg,.jpeg,.gif,.txt,.eml" 
                onChange={(e) => {
                  if (e.target.files && e.target.files.length > 0) {
                    handleAddAttachments(e.target.files);
                    e.target.value = ''; // Reset input so same file can be re-selected if needed
                  }
                }} 
              />

              {/* Upload Drop Trigger */}
              <div
                onDragEnter={handleAttachmentDrag}
                onDragLeave={handleAttachmentDrag}
                onDragOver={handleAttachmentDrag}
                onDrop={handleAttachmentDrop}
                onClick={() => attachmentInputRef.current?.click()}
                className={`flex items-center justify-between gap-3 px-4 py-2.5 bg-[#0f111a] backdrop-blur-xl border rounded-xl shadow-[0_0_20px_rgba(0,0,0,0.8)] transition-all duration-300 cursor-pointer ${
                  attachmentDragActive
                    ? 'border-cyan-500 bg-[#161925]'
                    : 'border-slate-700 hover:border-cyan-500/50 hover:bg-[#161925]'
                }`}
              >
                <div className="flex items-center gap-2.5 min-w-0">
                  <div className="w-7 h-7 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center shrink-0">
                    <Paperclip className="w-3.5 h-3.5 text-cyan-400" />
                  </div>
                  <div className="text-left truncate">
                    <span className="text-xs font-bold text-slate-200 tracking-wide block truncate">
                      {attachments.length > 0 ? `Attach More Files (${attachments.length} attached)` : "Upload Email Attachments (Optional)"}
                    </span>
                    <span className="text-[10px] text-zinc-500 block">PDF documents, QR code images, or forensic telemetry</span>
                  </div>
                </div>

                <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-zinc-900 border border-zinc-700/60 text-cyan-400 text-[10px] font-bold uppercase tracking-wider shrink-0 group-hover:border-cyan-500/50">
                  <Plus className="w-3 h-3" />
                  <span>Browse</span>
                </div>
              </div>

              {/* Attached Files Pill / Card List with Individual File Deletion */}
              {attachments.length > 0 && (
                <div className="flex flex-col gap-1.5 p-2 bg-zinc-950/60 border border-zinc-800/80 rounded-xl animate-in fade-in duration-200 max-h-48 overflow-y-auto custom-scrollbar">
                  <div className="flex items-center justify-between px-2 py-0.5 text-[9px] font-bold uppercase tracking-wider text-zinc-500">
                    <span>Enqueued Attachments ({attachments.length})</span>
                    <button 
                      type="button"
                      onClick={() => setAttachments([])}
                      className="hover:text-rose-400 transition-colors"
                    >
                      Clear All
                    </button>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-1.5">
                    {attachments.map((file, idx) => (
                      <div 
                        key={`${file.name}-${idx}`}
                        className="flex items-center justify-between gap-2 px-3 py-2 rounded-lg bg-[#0f111a] border border-zinc-800/80 hover:border-cyan-500/40 transition-colors group"
                      >
                        <div className="flex items-center gap-2 min-w-0">
                          <FileImage className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                          <div className="min-w-0">
                            <p className="text-[11px] text-zinc-200 font-mono truncate font-medium max-w-[140px] sm:max-w-[160px]" title={file.name}>
                              {file.name}
                            </p>
                            <div className="flex items-center gap-1.5 mt-0.5">
                              {getFileBadge(file.name)}
                              <span className="text-[9px] text-zinc-500 font-mono">{formatFileSize(file.size)}</span>
                            </div>
                          </div>
                        </div>

                        {/* Individual "X" / Delete Button */}
                        <button
                          type="button"
                          onClick={(e) => {
                            e.stopPropagation();
                            handleRemoveAttachment(idx);
                          }}
                          className="p-1 rounded-md text-zinc-500 hover:text-rose-400 hover:bg-rose-500/10 transition-colors shrink-0"
                          title="Remove this attachment"
                        >
                          <X className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
      
      {/* DLP PII Masking Toggle Switch */}
      <div className="bg-[#0f111a] backdrop-blur-xl border border-slate-700/80 hover:border-cyan-500/40 rounded-2xl p-3.5 sm:p-4 shadow-[0_0_20px_rgba(0,0,0,0.8)] transition-all duration-300">
        <div className="flex items-center justify-between gap-3">
          <div className="flex items-center gap-3 min-w-0">
            <div className={`w-9 h-9 rounded-xl border flex items-center justify-center shrink-0 transition-colors ${
              dlpMasking
                ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400 shadow-[0_0_12px_rgba(16,185,129,0.2)]'
                : 'bg-rose-500/10 border-rose-500/30 text-rose-400 shadow-[0_0_12px_rgba(244,63,94,0.2)]'
            }`}>
              {dlpMasking ? <ShieldCheck className="w-5 h-5" /> : <ShieldAlert className="w-5 h-5" />}
            </div>
            <div className="min-w-0">
              <div className="flex items-center gap-2">
                <span className="text-xs sm:text-sm font-bold text-slate-100 tracking-wide">DLP PII Masking</span>
                <span className={`text-[9px] font-bold uppercase tracking-wider px-2 py-0.5 rounded-full border ${
                  dlpMasking
                    ? 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30'
                    : 'bg-rose-500/15 text-rose-400 border-rose-500/30 animate-pulse'
                }`}>
                  {dlpMasking ? 'Active' : 'Bypassed'}
                </span>
              </div>
              <p className="text-[10px] sm:text-xs text-zinc-400 mt-0.5 leading-relaxed">
                {dlpMasking
                  ? 'Redacts cards, IBANs, phone numbers & PII in-memory before AI reasoning'
                  : 'Warning: Raw text & PII exposed to AI unmasked. Compliance liability disclaimed.'}
              </p>
            </div>
          </div>

          <button
            type="button"
            role="switch"
            aria-checked={dlpMasking}
            onClick={() => setDlpMasking(!dlpMasking)}
            className={`relative inline-flex h-6 w-11 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-300 ease-in-out focus:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400 ${
              dlpMasking ? 'bg-cyan-500 shadow-[0_0_15px_rgba(6,182,212,0.5)]' : 'bg-zinc-800'
            }`}
          >
            <span
              className={`pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow-md ring-0 transition duration-300 ease-in-out ${
                dlpMasking ? 'translate-x-5' : 'translate-x-0'
              }`}
            />
          </button>
        </div>
      </div>

      <button 
        type="button"
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
