/**
 * VAJRA Digital Forensic Platform - Certified PDF Export Client
 * Downloads cryptographic in-memory PDF dossier directly from FastAPI backend.
 */
export async function downloadCasePdf(caseId) {
  if (!caseId) {
    throw new Error('No Case ID available for PDF export.');
  }

  const cleanId = String(caseId).trim();
  const url = `http://localhost:8000/api/v1/cases/${encodeURIComponent(cleanId)}/pdf`;

  const response = await fetch(url);
  if (!response.ok) {
    let errorDetail = `HTTP ${response.status}`;
    try {
      const errJson = await response.json();
      errorDetail = errJson.error?.message || errJson.detail || errorDetail;
    } catch {
      // Not JSON
    }
    throw new Error(`PDF generation failed (${errorDetail})`);
  }

  const blob = await response.blob();
  const blobUrl = window.URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = blobUrl;
  link.download = `VAJRA_CASE_${cleanId}.pdf`;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  window.URL.revokeObjectURL(blobUrl);
}
