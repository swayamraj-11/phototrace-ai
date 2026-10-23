"""
Error Level Analysis (ELA) Module for PhotoTrace AI.

Generates an experimental ELA visualization by resaving the image
at a known quality level (92%) and magnifying the pixel error variance.
"""

import io
import base64
from PIL import Image, ImageChops, ImageEnhance


def generate_ela(file_path: str, quality: int = 92, scale: int = 15) -> dict:
    """
    Computes Error Level Analysis for the provided image file.
    
    Returns:
        dict containing:
        - ela_image_base64: PNG base64 representation of the ELA visual
        - explanation: Clear educational interpretation
        - disclaimer: Forensic limitations
    """
    try:
        with Image.open(file_path) as original:
            original = original.convert("RGB")
            
            # Temporary in-memory resave at known quality
            buffer = io.BytesIO()
            original.save(buffer, "JPEG", quality=quality)
            buffer.seek(0)
            
            with Image.open(buffer) as resaved:
                # Calculate pixel-by-pixel difference
                diff = ImageChops.difference(original, resaved)
                
                # Enhance difference for visual clarity
                extrema = diff.getextrema()
                max_diff = max([ex[1] for ex in extrema])
                if max_diff == 0:
                    max_diff = 1
                
                # Scale up errors
                scale_factor = 255.0 / max_diff if max_diff < 50 else scale
                enhancer = ImageEnhance.Brightness(diff)
                ela_img = enhancer.enhance(scale_factor)
                
                # Save ELA image to base64
                out_buf = io.BytesIO()
                ela_img.save(out_buf, format="PNG")
                ela_base64 = base64.b64encode(out_buf.getvalue()).decode("ascii")
                
                return {
                    "available": True,
                    "ela_image_base64": f"data:image/png;base64,{ela_base64}",
                    "quality_level": quality,
                    "explanation": (
                        "Error Level Analysis (ELA) highlights areas with different JPEG compression levels. "
                        "Surfaces with uniform textures should show similar error rates. High-contrast edges "
                        "naturally exhibit higher error rates. Unusually bright or inconsistent regions may suggest "
                        "pasting from another image or localized re-saving."
                    ),
                    "disclaimer": (
                        "EXPERIMENTAL FORENSIC VISUALIZATION: ELA is an investigative aid, NOT definitive proof "
                        "of manipulation. Textures, sharp geometric boundaries, and natural lighting gradients "
                        "also induce elevated ELA readings."
                    ),
                }
    except Exception as e:
        return {
            "available": False,
            "error": f"ELA generation failed: {str(e)}",
            "disclaimer": "ELA requires raster image rendering.",
        }
