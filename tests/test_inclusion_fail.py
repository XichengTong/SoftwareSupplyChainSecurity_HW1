# tests/test_inclusion_errors.py
import pytest
import os
import json
import main  # Import your main project file
from jsonschema import validate

def test_inclusion_failed_inclusion_proof_fetch():
    # Mock get_verification_proof to return None
    original_get_verification_proof = main.get_verification_proof
    main.get_verification_proof = lambda *args, **kwargs: None

    # Mock valid artifact verification, public key extraction, and log entry
    main.get_log_entry = lambda *args, **kwargs: {"public_key": "dGVzdF9wdWJsaWNfa2V5", "signature": "dGVzdF9zaWduYXR1cmU="}
    main.extract_public_key = lambda *args, **kwargs: b"test_public_key_bytes"
    main.verify_artifact_signature = lambda *args, **kwargs: True

    # Test when inclusion proof fetching fails
    result = main.inclusion(130322369, "artifact.md", debug=True)
    assert result is False

    # Restore the original function
    main.get_verification_proof = original_get_verification_proof

def test_inclusion_incomplete_inclusion_proof():
    # Mock get_verification_proof to return incomplete data
    original_get_verification_proof = main.get_verification_proof
    main.get_verification_proof = lambda *args, **kwargs: {"leaf_hash": None}

    # Mock valid artifact verification, public key extraction, and log entry
    main.get_log_entry = lambda *args, **kwargs: {"public_key": "dGVzdF9wdWJsaWNfa2V5", "signature": "dGVzdF9zaWduYXR1cmU="}
    main.extract_public_key = lambda *args, **kwargs: b"test_public_key_bytes"
    main.verify_artifact_signature = lambda *args, **kwargs: True

    # Test when inclusion proof data is incomplete
    result = main.inclusion(130322369, "artifact.md", debug=True)
    assert result is False

    # Restore the original function
    main.get_verification_proof = original_get_verification_proof