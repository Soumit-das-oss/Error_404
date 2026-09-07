"""
VAJRA Forensic Platform - Isolated QR / Quishing Engine
Safe, zero-crash zxing-cpp wrapper with polarity inversion for dark-mode QR codes.
"""

import io
import logging
from typing import List, Union
from PIL import Image, ImageOps

logger = logging.getLogger("vajra.analyzers.qr")

try:
    import zxingcpp
except ImportError:
    zxingcpp = None


def extract_qr_codes(images: List[Union[bytes, Image.Image]]) -> List[str]:
    """Safely decode QR code URLs from image bytes or PIL Images.

    Returns empty list on any decompression or decoding failure; never raises.
    """
    if not images or zxingcpp is None:
        return []

    decoded_urls: List[str] = []

    for img_input in images:
        try:
            # Normalize to PIL Image
            if isinstance(img_input, bytes):
                if not img_input:
                    continue
                pil_img = Image.open(io.BytesIO(img_input))
            elif isinstance(img_input, Image.Image):
                pil_img = img_input
            else:
                continue

            # Pass 1: Standard contrast read
            results = zxingcpp.read_barcodes(pil_img)
            for r in results:
                text = (r.text or "").strip()
                if text and (text.startswith("http://") or text.startswith("https://") or "://" in text):
                    if text not in decoded_urls:
                        decoded_urls.append(text)

            # Pass 2: Inverted polarity for dark-mode / inverted QR codes
            if not results:
                try:
                    inverted_img = ImageOps.invert(pil_img.convert("RGB"))
                    inv_results = zxingcpp.read_barcodes(inverted_img)
                    for r in inv_results:
                        text = (r.text or "").strip()
                        if text and (text.startswith("http://") or text.startswith("https://") or "://" in text):
                            if text not in decoded_urls:
                                decoded_urls.append(text)
                except Exception:
                    pass

        except Exception as e:
            logger.debug(f"QR decoding skipped image due to: {e}")
            continue

    return decoded_urls
