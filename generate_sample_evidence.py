"""
Helper script to generate sample forensic evidence images for testing PhotoTrace AI.
Creates:
1. sample_camera_photo.jpg (Full EXIF, GPS location in Paris/Eiffel Tower, Camera specs)
2. sample_social_media_stripped.jpg (Stripped metadata as happens on WhatsApp/Signal)
3. sample_photoshop_edited.jpg (Edited copy with Adobe tag and dimension crop)
"""

import os
from PIL import Image
from PIL.TiffImagePlugin import IFDRational

def generate_samples(output_dir="sample_evidence"):
    os.makedirs(output_dir, exist_ok=True)
    
    # 1. Camera Original with EXIF and GPS (Eiffel Tower, Paris: 48°51'29.6" N, 2°17'40.2" E)
    img1_path = os.path.join(output_dir, "sample_camera_photo.jpg")
    img1 = Image.new("RGB", (1200, 800), color=(24, 40, 68))
    
    exif = img1.getexif()
    exif[0x010F] = "Sony"
    exif[0x0110] = "ILCE-7RM4"
    exif[0x0132] = "2024:08:14 16:30:00"
    
    sub_ifd = exif.get_ifd(0x8769)
    sub_ifd[0x9003] = "2024:08:14 16:30:00" # DateTimeOriginal
    sub_ifd[0x9004] = "2024:08:14 16:30:00" # DateTimeDigitized
    sub_ifd[0x829A] = IFDRational(1, 500)   # 1/500s
    sub_ifd[0x829D] = IFDRational(4, 1)     # f/4
    sub_ifd[0x8827] = 100                   # ISO 100
    sub_ifd[0x920A] = IFDRational(35, 1)    # 35mm
    sub_ifd[0x9209] = 0                     # Flash did not fire
    sub_ifd[0xA434] = "FE 35mm F1.4 GM"
    
    gps_ifd = exif.get_ifd(0x8825)
    gps_ifd[1] = "N"
    gps_ifd[2] = (IFDRational(48, 1), IFDRational(51, 1), IFDRational(296, 10))
    gps_ifd[3] = "E"
    gps_ifd[4] = (IFDRational(2, 1), IFDRational(17, 1), IFDRational(402, 10))
    gps_ifd[6] = IFDRational(35, 1)

    img1.save(img1_path, "JPEG", exif=exif, quality=95)
    print(f"Generated: {img1_path}")

    # 2. Stripped Copy (Simulating WhatsApp / Telegram upload)
    img2_path = os.path.join(output_dir, "sample_social_media_stripped.jpg")
    img2 = Image.new("RGB", (800, 533), color=(24, 40, 68))
    img2.save(img2_path, "JPEG", quality=80) # Clean stripped image
    print(f"Generated: {img2_path}")

    # 3. Edited Copy with Adobe Photoshop signature
    img3_path = os.path.join(output_dir, "sample_photoshop_edited.jpg")
    img3 = Image.new("RGB", (1000, 600), color=(40, 60, 90))
    exif3 = img3.getexif()
    exif3[0x0131] = "Adobe Photoshop 2024 (Windows)"
    exif3[0x0132] = "2024:08:15 19:10:00"
    sub_ifd3 = exif3.get_ifd(0x8769)
    sub_ifd3[0x9003] = "2024:08:14 16:30:00"
    img3.save(img3_path, "JPEG", exif=exif3, quality=90)
    print(f"Generated: {img3_path}")

if __name__ == "__main__":
    generate_samples()
