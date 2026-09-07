"""
VAJRA Forensic Platform - Isolated PyMuPDF In-Memory PDF Engine
Extracts hyperlinks, visible anchor texts, and embedded images without disk writes.
"""

import logging
import re
from typing import Dict, Any, List
from app.analyzers.url_analyzer import check_deceptive_link

logger = logging.getLogger("vajra.analyzers.pdf")

try:
    import pymupdf as fitz
except ImportError:
    try:
        import fitz
    except ImportError:
        fitz = None

DANGEROUS_EXTS_BYTES = [
    b".exe", b".scr", b".bat", b".cmd", b".ps1", b".vbs", b".hta", b".dll", b".pif", b".iso", b".jar", b".msi"
]


def extract_pdf_telemetry(pdf_bytes: bytes) -> Dict[str, Any]:
    """Inspect PDF stream in-memory for hyperlinks, deceptive anchors, active JS/Launch scripts, and raster images.

    Returns:
      {
          "links": list[str],
          "deceptive_links": list[dict],
          "images": list[bytes],
          "text": str,
          "has_javascript": bool,
          "has_launch_action": bool,
          "suspicious_indicators": list[str],
          "is_authentic": bool,
      }
    """
    has_javascript = False
    has_launch_action = False
    suspicious_indicators: List[str] = []

    if pdf_bytes:
        pdf_lower = pdf_bytes.lower()

        # 1. Forensic scan for /JavaScript or /JS active execution objects
        if re.search(rb"/(?:javascript|js)\s*[<<\[/(\n\r]", pdf_bytes, re.IGNORECASE) or re.search(rb"/type\s*/action\s*/s\s*/javascript", pdf_bytes, re.IGNORECASE):
            has_javascript = True
            suspicious_indicators.append("Embedded /JavaScript or /JS active execution stream")

        # 2. Forensic scan for /Launch process action
        if re.search(rb"/launch\s*[<<\[/(\n\r]", pdf_bytes, re.IGNORECASE) or re.search(rb"/type\s*/action\s*/s\s*/launch", pdf_bytes, re.IGNORECASE):
            has_launch_action = True
            suspicious_indicators.append("Embedded /Launch system process action")

        # 3. Forensic scan for /EmbeddedFiles targeting executable binaries
        if re.search(rb"/embeddedfiles\b", pdf_bytes, re.IGNORECASE):
            for ext in DANGEROUS_EXTS_BYTES:
                if ext in pdf_lower:
                    has_launch_action = True
                    suspicious_indicators.append(f"Embedded executable payload ({ext.decode('ascii', errors='ignore')})")
                    break

    telemetry: Dict[str, Any] = {
        "links": [],
        "deceptive_links": [],
        "images": [],
        "text": "",
        "has_javascript": has_javascript,
        "has_launch_action": has_launch_action,
        "suspicious_indicators": suspicious_indicators,
        "is_authentic": (not has_javascript and not has_launch_action),
    }

    if not pdf_bytes or fitz is None:
        return telemetry

    doc = None
    try:
        doc = fitz.open(stream=pdf_bytes, filetype="pdf")
        text_parts: List[str] = []

        # Check embedded files via PyMuPDF if available
        try:
            if hasattr(doc, "embfile_count") and doc.embfile_count() > 0:
                for fname in doc.embfile_names():
                    fname_lower = fname.lower()
                    if any(fname_lower.endswith(ext.decode("ascii")) for ext in DANGEROUS_EXTS_BYTES):
                        telemetry["has_launch_action"] = True
                        if f"Embedded executable file: {fname}" not in telemetry["suspicious_indicators"]:
                            telemetry["suspicious_indicators"].append(f"Embedded executable file: {fname}")
        except Exception:
            pass

        for page_idx in range(len(doc)):
            page = doc[page_idx]

            # 1. Page text
            page_text = page.get_text()
            if page_text:
                text_parts.append(page_text)

            # 2. Hyperlinks & visible anchor text
            try:
                links = page.get_links()
                for lnk in links:
                    uri = (lnk.get("uri") or "").strip()
                    if uri and (uri.startswith("http://") or uri.startswith("https://")):
                        if uri not in telemetry["links"]:
                            telemetry["links"].append(uri)

                        # Bounding box anchor text
                        rect = lnk.get("from")
                        if rect:
                            try:
                                anchor_text = page.get_text("text", clip=rect).strip()
                                deceptive = check_deceptive_link(anchor_text, uri)
                                if deceptive and deceptive not in telemetry["deceptive_links"]:
                                    telemetry["deceptive_links"].append(deceptive)
                            except Exception:
                                pass
            except Exception:
                pass

            # 3. Extract raster images from PDF for vision / QR analysis
            try:
                image_list = page.get_images(full=True)
                for img_item in image_list:
                    xref = img_item[0]
                    base_img = doc.extract_image(xref)
                    img_bytes = base_img.get("image")
                    if img_bytes:
                        telemetry["images"].append(img_bytes)
            except Exception:
                pass

        telemetry["text"] = "\n".join(text_parts).strip()
        telemetry["is_authentic"] = (not telemetry["has_javascript"] and not telemetry["has_launch_action"] and len(telemetry["deceptive_links"]) == 0)

    except Exception as e:
        logger.debug(f"PyMuPDF in-memory parsing skipped due to: {e}")
    finally:
        if doc is not None:
            try:
                doc.close()
            except Exception:
                pass

    return telemetry
