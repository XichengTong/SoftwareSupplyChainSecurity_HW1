
import pytest
import myproject.merkle_proof as merkle_proof  
from jsonschema import validate

def test_verify_consistency_invalid_proof_size():
    # Prepare the data for the verify_consistency function with an invalid proof size
    hasher = merkle_proof.DefaultHasher  # Use the hasher class without instantiating it
    size1 = 3
    size2 = 6
    proof = [
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"  # Incorrect proof size
    ]
    root1 = "7a65e1ac0d02fb5e6ac21f9ef567d6c7b6ecae7f6b90a1449a02d8dd0c6acdf9"
    root2 = "54f6b681d34a6f4c84ec71a2b4e3f4c1dfe4e5b28e9f9c7738bfbfd1c576ca8c"

    # Verify that a ValueError is raised due to incorrect proof size
    with pytest.raises(ValueError, match="wrong bytearray_proof size"):
        merkle_proof.verify_consistency(hasher, size1, size2, proof, root1, root2)

def test_chain_inner():
    # Prepare the data for the chain_inner function
    hasher = merkle_proof.DefaultHasher  # Use the hasher class without instantiating it
    seed = bytes.fromhex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    proof = [
        bytes.fromhex("5b4b784fbda2f0eae46e029b8f6eb26b2bf9c2fb784556773d9e9a1e1c68f6c1"),
        bytes.fromhex("6e7f6f9f8a1d4e8b6b21d5c4b6e9a8b1c3d5e4f6a8b1c6e9b4e5c6d7e8f9a1b2")
    ]
    index = 3

    # Call the chain_inner function
    result = merkle_proof.chain_inner(hasher, seed, proof, index)

    # Verify the result is a bytes object
    assert isinstance(result, bytes)
    
# Test for chain_inner_right function
def test_chain_inner_right():
    hasher = merkle_proof.DefaultHasher
    seed = b"seed_hash"
    proof = [
        b"proof_hash_1",
        b"proof_hash_2"
    ]
    index = 3

    # Call chain_inner_right function
    result = merkle_proof.chain_inner_right(hasher, seed, proof, index)

    # Check if the result is a byte object
    assert isinstance(result, bytes)

# Test for chain_border_right function
def test_chain_border_right():
    hasher = merkle_proof.DefaultHasher
    seed = b"seed_hash"
    proof = [
        b"proof_hash_1",
        b"proof_hash_2"
    ]

    # Call chain_border_right function
    result = merkle_proof.chain_border_right(hasher, seed, proof)

    # Check if the result is a byte object
    assert isinstance(result, bytes)