# tests/test_last_checkpoint.py
import sys
import json
from jsonschema import validate
import subprocess
import myproject.main as main  

checkpoint_schema = {
    "type": "object",
    "properties": {
        "inactiveShards": {"type": "array"},
        "rootHash": {"type": "string"},
        "signedTreeHead": {"type": "string"},
        "treeID": {"type": "string"},
        "treeSize": {"type": "integer"},
    },
    "required": ["inactiveShards", "rootHash", "signedTreeHead", "treeID", "treeSize"]
}

def test_checkpoint():
    result = subprocess.run(
        [sys.executable, 'src/myproject/main.py', '-c'],
        capture_output=True,
        text=True
    )

    output = result.stdout
    data = json.loads(output)

    # Validate structure of checkpoint
    validate(instance=data, schema=checkpoint_schema)

#if __name__ == "__main__":
#    test_checkpoint()
