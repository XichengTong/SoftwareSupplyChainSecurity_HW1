import pytest
import os
import json
import main  
from jsonschema import validate

def test_inclusion_failed_public_key_extraction():
    # Mock extract_public_key to return None
    original_extract_public_key = main.extract_public_key
    main.extract_public_key = lambda *args, **kwargs: None

    # Mock get_log_entry to return valid data
    original_get_log_entry = main.get_log_entry
    main.get_log_entry = lambda *args, **kwargs: {"public_key": "dGVzdF9wdWJsaWNfa2V5", "signature": "dGVzdF9zaWduYXR1cmU="}

    # Test when public key extraction fails
    result = main.inclusion(130322369, "artifact.md", debug=True)
    assert result is False

    # Restore the original functions
    main.extract_public_key = original_extract_public_key
    main.get_log_entry = original_get_log_entry