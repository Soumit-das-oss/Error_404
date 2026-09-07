"""
VAJRA Forensic Platform - Isolated PyMuPDF In-Memory PDF Engine
Extracts hyperlinks, visible anchor texts, and embedded images without disk writes.
"""

import logging
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


def extract_pdf_telemetry(pdf_bytes: bytes) -> Dict[str, Any]:
    """Inspect PDF stream in-memory for hyperlinks, deceptive anchors, and raster images.

    Returns:
      {"links": list[str], "deceptive_links": list[dict], "images": list[bytes], "text": str}
    """
    telemetry = {
        "links": [],
        "deceptive_links": [],
        "images": [],
        "text": "",
    }

    if not pdf_bytes or fitz is None:
        return telemetry

    doc = None
    try:
        doc = fitz.open(stream=pdf_bytes, filetype="pdf")
        text_parts: List[str] = []

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

    except Exception as e:
        logger.debug(f"PyMuPDF in-memory parsing skipped due to: {e}")
    finally:
        if doc is not None:
            try:
                doc.close()
            except Exception:
                pass

    return telemetry
