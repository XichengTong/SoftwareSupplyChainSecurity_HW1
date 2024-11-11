import pytest
import json
from jsonschema import validate
import main  

# Define the JSON schema for the expected response
verification_proof_schema = {
    "type": "object",
    "properties": {
        "leaf_hash": {"type": "string"},
        "index": {"type": "integer"},
        "tree_size": {"type": "integer"},
        "root_hash": {"type": "string"},
        "hashes": {"type": "array", "items": {"type": "string"}}
    },
    "required": ["leaf_hash", "index", "tree_size", "root_hash", "hashes"]
}

# Test function for get_verification_proof()
def test_get_verification_proof():
    # Use the provided log index
    log_index = 130322369
    
    # Call the function with debug mode on to see extra info
    result = main.get_verification_proof(log_index, debug=True)

    # Validate the result with JSON schema if the response is not None
    if result is not None:
        validate(instance=result, schema=verification_proof_schema)
    
    # Assert that the result is not None and has the expected keys
    assert result is not None
    assert "leaf_hash" in result
    assert "index" in result
    assert "tree_size" in result
    assert "root_hash" in result
    assert "hashes" in result

