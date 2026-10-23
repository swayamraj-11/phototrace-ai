"""
Unit tests for cryptographic hashing correctness.
"""

import hashlib
import tempfile
import os
from backend.metadata_extractor import calculate_file_hash


def test_sha256_known_vector():
    """Verify calculate_file_hash against standard Python hashlib test."""
    test_content = b"PhotoTrace AI Forensic Test Payload - 2026"
    expected_hash = hashlib.sha256(test_content).hexdigest()

    with tempfile.NamedTemporaryFile(delete=False) as tf:
        tf.write(test_content)
        temp_path = tf.name

    try:
        calculated_hash = calculate_file_hash(temp_path, "sha256")
        assert calculated_hash == expected_hash
        assert len(calculated_hash) == 64
        # Hash must be hexadecimal characters
        assert all(c in "0123456789abcdef" for c in calculated_hash)
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


def test_hash_differentiation():
    """Ensure two different file contents never yield identical hashes."""
    with tempfile.NamedTemporaryFile(delete=False) as tf1, tempfile.NamedTemporaryFile(delete=False) as tf2:
        tf1.write(b"Evidence Copy Alpha")
        tf2.write(b"Evidence Copy Beta")
        p1, p2 = tf1.name, tf2.name

    try:
        h1 = calculate_file_hash(p1)
        h2 = calculate_file_hash(p2)
        assert h1 != h2
    finally:
        if os.path.exists(p1): os.remove(p1)
        if os.path.exists(p2): os.remove(p2)
