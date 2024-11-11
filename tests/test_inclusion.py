# tests/test_inclusion_errors.py
import pytest
import os
import json
import main  # Import your main project file
from jsonschema import validate

def test_inclusion_invalid_log_index():
    # Test for invalid log index (negative value)
    with pytest.raises(ValueError, match="Log index must be a non-negative integer."):
        main.inclusion(-1, "artifact.md", debug=True)

def test_inclusion_missing_artifact():
    # Test for non-existing artifact file path
    with pytest.raises(ValueError, match="Artifact file .* does not exist."):
        main.inclusion(130322369, "non_existing_artifact.md", debug=True)

def test_inclusion_missing_key_or_signature():
    # Mock get_log_entry to return incomplete data
    original_get_log_entry = main.get_log_entry
    main.get_log_entry = lambda *args, **kwargs: {"public_key": None, "signature": None}

    # Test when public key or signature is missing
    result = main.inclusion(130322369, "artifact.md", debug=True)
    assert result is False

    # Restore the original function
    main.get_log_entry = original_get_log_entry

if __name__ == "__main__":
    pytest.main()