import pytest
import json
from jsonschema import validate
import main  # Import your main project file

# Define the JSON schema for the expected response
log_entry_schema = {
    "type": "object",
    "properties": {
        "signature": {"type": "string"},
        "public_key": {"type": "string"}
    },
    "required": ["signature", "public_key"]
}

# Test function for get_log_entry()
def test_get_log_entry():
    # Use the provided log index
    log_index = 130322369
    
    # Call the function with debug mode on to see extra info
    result = main.get_log_entry(log_index, debug=True)

    # Validate the result with JSON schema if the response is not None
    if result is not None:
        validate(instance=result, schema=log_entry_schema)
    
    # Assert that the result is not None and has the expected keys
    assert result is not None
    assert "signature" in result
    assert "public_key" in result

#if __name__ == "__main__":
#   pytest.main()
