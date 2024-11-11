import pytest
import json
from jsonschema import validate
import main  # Import your main project file

# Define the JSON schema for the previous checkpoint
checkpoint_schema = {
    "type": "object",
    "properties": {
        "treeID": {"type": "string"},
        "treeSize": {"type": "integer"},
        "rootHash": {"type": "string"}
    },
    "required": ["treeID", "treeSize", "rootHash"]
}

# Test function for consistency()
def test_consistency():
    # Create a mock previous checkpoint with the actual information
    prev_checkpoint = {
        "treeID": "1193050959916656506",
        "treeSize": 130322369,
        "rootHash": "3a6f8e5dbecd94c4b1e8bf0ed98bc99a0bf405d5411e31445e3a6e73e1234567"
    }
    
    # Validate the mock previous checkpoint with JSON schema
    validate(instance=prev_checkpoint, schema=checkpoint_schema)

    # Call the function to check consistency
    result = main.consistency(prev_checkpoint, debug=True)

    # Assert that the result is a boolean value (True/False)
    assert isinstance(result, bool)

