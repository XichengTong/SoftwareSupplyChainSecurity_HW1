# tests/test_main.py
import pytest
import subprocess
import sys

# Test for main.py consistency part
def test_main_consistency_missing_args():
    """
    Test for missing arguments in consistency check.
    This test will check if the script returns the expected output when required arguments are missing.
    """
    # Test case when tree_id is not provided
    result = subprocess.run(
        [sys.executable, "main.py", "--consistency", "--tree-size", "26102321", "--root-hash", "42a074539f68d47a158a74095090ee0b54908b1392c2021561bdea9fe5df8943"],
        capture_output=True,
        text=True
    )
    assert "please specify tree id for prev checkpoint" in result.stdout

    # Test case when tree_size is not provided
    result = subprocess.run(
        [sys.executable, "main.py", "--consistency", "--tree-id", "1193050959916656506", "--root-hash", "42a074539f68d47a158a74095090ee0b54908b1392c2021561bdea9fe5df8943"],
        capture_output=True,
        text=True
    )
    assert "please specify tree size for prev checkpoint" in result.stdout

    # Test case when root_hash is not provided
    result = subprocess.run(
        [sys.executable, "main.py", "--consistency", "--tree-id", "1193050959916656506", "--tree-size", "26102321"],
        capture_output=True,
        text=True
    )
    assert "please specify root hash for prev checkpoint" in result.stdout

if __name__ == "__main__":
    pytest.main()
