"""
Pytest configuration and programmatic test image fixtures.
Generates synthetic valid images with/without EXIF, GPS, and corruption.
"""

import os
import io
import pytest
from PIL import Image
from PIL.TiffImagePlugin import IFDRational


@pytest.fixture(scope="session")
def test_images_dir(tmp_path_factory):
    """Creates a temporary directory for synthetic test images."""
    temp_dir = tmp_path_factory.mktemp("forensic_test_data")
    return str(temp_dir)


@pytest.fixture(scope="session")
def image_with_exif_and_gps(test_images_dir):
    """
    Creates a valid JPEG image with programmatic EXIF tags and GPS coordinates.
    GPS: 37°46'29.76" N, 122°25'09.84" W (San Francisco, CA)
    """
    img_path = os.path.join(test_images_dir, "sample_with_exif_gps.jpg")
    img = Image.new("RGB", (640, 480), color=(30, 80, 150))
    
    exif = img.getexif()
    # Make & Model
    exif[0x010F] = "Nikon Corp"       # Make
    exif[0x0110] = "NIKON D850"       # Model
    exif[0x0131] = "Adobe Photoshop 2024" # Software
    exif[0x0132] = "2024:06:15 12:45:00" # DateTime
    
    # EXIF Sub-IFD (0x8769)
    exif_ifd = exif.get_ifd(0x8769)
    exif_ifd[0x9003] = "2024:06:15 10:15:30" # DateTimeOriginal
    exif_ifd[0x9004] = "2024:06:15 10:15:30" # DateTimeDigitized
    exif_ifd[0x829A] = IFDRational(1, 250)   # ExposureTime 1/250
    exif_ifd[0x829D] = IFDRational(28, 10)   # FNumber 2.8
    exif_ifd[0x8827] = 200                   # ISO
    exif_ifd[0x920A] = IFDRational(50, 1)    # FocalLength 50mm
    exif_ifd[0x9209] = 16                    # Flash did not fire
    exif_ifd[0xA434] = "AF-S NIKKOR 50mm f/1.8G" # LensModel

    # GPS Sub-IFD (0x8825)
    gps_ifd = exif.get_ifd(0x8825)
    gps_ifd[1] = "N"                         # GPSLatitudeRef
    gps_ifd[2] = (IFDRational(37, 1), IFDRational(46, 1), IFDRational(2976, 100)) # 37 deg 46 min 29.76 sec
    gps_ifd[3] = "W"                         # GPSLongitudeRef
    gps_ifd[4] = (IFDRational(122, 1), IFDRational(25, 1), IFDRational(984, 100)) # 122 deg 25 min 9.84 sec
    gps_ifd[6] = IFDRational(45, 1)          # Altitude 45m

    img.save(img_path, "JPEG", exif=exif)
    return img_path


@pytest.fixture(scope="session")
def image_without_exif(test_images_dir):
    """Creates a clean PNG image with zero EXIF metadata (representing stripped file)."""
    img_path = os.path.join(test_images_dir, "sample_stripped.png")
    img = Image.new("RGB", (320, 240), color=(18, 24, 38))
    img.save(img_path, "PNG")
    return img_path


@pytest.fixture(scope="session")
def image_with_exif_no_gps(test_images_dir):
    """Creates a JPEG with camera metadata but no GPS coordinates."""
    img_path = os.path.join(test_images_dir, "sample_no_gps.jpg")
    img = Image.new("RGB", (800, 600), color=(50, 120, 90))
    exif = img.getexif()
    exif[0x010F] = "Canon"
    exif[0x0110] = "Canon EOS R5"
    
    exif_ifd = exif.get_ifd(0x8769)
    exif_ifd[0x9003] = "2023:11:04 09:20:10"
    exif_ifd[0x8827] = 400
    img.save(img_path, "JPEG", exif=exif)
    return img_path


@pytest.fixture(scope="session")
def corrupt_image_file(test_images_dir):
    """Creates a corrupt file starting with JPEG magic bytes but containing garbage."""
    file_path = os.path.join(test_images_dir, "corrupt_image.jpg")
    with open(file_path, "wb") as f:
        f.write(b"\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00corrupt_random_data_stream_1234567890")
    return file_path


@pytest.fixture(scope="session")
def non_image_file(test_images_dir):
    """Creates a text file masquerading with an image extension."""
    file_path = os.path.join(test_images_dir, "fake_image.jpg")
    with open(file_path, "w") as f:
        f.write("This is a plain text file, not a genuine image binary.")
    return file_path
