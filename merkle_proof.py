"""
Merkle Tree Proof Verification Utilities.

This module provides functions to verify Merkle tree inclusion and consistency proofs, 
following the RFC 6962 specification for transparency logs such as Rekor.

Classes:
    Hasher: 
        A class for computing hashes of Merkle tree leaves and nodes.
    
    RootMismatchError:
        Custom exception raised when a calculated Merkle tree root hash 
        does not match the expected root hash.

Functions:
    verify_consistency(hasher, checkpoint1: Checkpoint, checkpoint2: Checkpoint, proof):
        Verifies the consistency between two checkpoints 
        in the Merkle tree using a consistency proof.
    
    verify_inclusion(hasher, index, size, leaf_hash, proof, root, debug=False):
        Verifies the inclusion of a leaf in the Merkle tree using an inclusion proof.

    compute_leaf_hash(body):
        Computes the hash of a leaf in the Merkle tree following RFC 6962.

    chain_inner, chain_inner_right, chain_border_right:
        Helper functions for calculating Merkle tree hashes based on the proof structure.

    decomp_incl_proof(index, size):
        Decomposes the inclusion proof into inner and border proof components.

    verify_match(calculated, expected):
        Verifies that the calculated root matches the expected root.

    root_from_inclusion_proof(hasher, index, size, leaf_hash, proof):
        Computes the root hash from a Merkle tree inclusion proof.
    
Usage:
    - Verify inclusion of entries in a transparency log.
    - Verify the consistency between two checkpoints of a Merkle tree.
"""
import hashlib
import binascii
import base64
from dataclasses import dataclass

@dataclass
class Checkpoint:
    """
    Represents a checkpoint in a Merkle tree, containing the size of the tree
    and the root hash at that checkpoint.

    Attributes:
        size (int): The size of the Merkle tree (number of leaves) at the checkpoint.
        root (str): The root hash of the Merkle tree at the checkpoint, as a hexadecimal string.
    """
    size: int
    root: str

@dataclass
class InclusionProof:
    """
    A data structure representing the proof of inclusion for a leaf in a Merkle tree.

    Attributes:
        index (int): The index of the leaf node within the Merkle tree.
        size (int): The total size of the Merkle tree (number of leaves).
        leaf_hash (str): The hash of the leaf node, represented as a hexadecimal string.
        proof (list of str): A list of hashes representing the Merkle proof for inclusion, 
                             where each hash is represented as a hexadecimal string.
        root (str): The expected root hash of the Merkle tree, represented as a hexadecimal string.
    """
    index: int
    size: int
    leaf_hash: str
    proof: list
    root: str

# domain separation prefixes according to the RFC
RFC6962_LEAF_HASH_PREFIX = 0
RFC6962_NODE_HASH_PREFIX = 1


class Hasher:
    """
    A generic class for hashing values for Merkle trees, supporting leaf and node hashing.

    Methods:
        new: Returns a new hash object using the specified hash function (default: SHA256).
        empty_root: Returns the hash of an empty root node.
        hash_leaf: Computes the hash of a leaf node with a domain separation prefix.
        hash_children: Computes the hash of two children nodes with a domain separation prefix.
        size: Returns the size of the digest produced by the hash function.
    """
    def __init__(self, hash_func=hashlib.sha256):
        self.hash_func = hash_func

    def new(self):
        """
    Creates and returns a new hash object using the specified hash function.

    Returns:
        hashlib._hashlib.HASH: A new instance of the hash function (e.g., SHA256).
        """
        return self.hash_func()

    def empty_root(self):
        """
    Computes and returns the hash of an empty root node in the Merkle tree.

    This method is used when there are no leaves in the Merkle tree.

    Returns:
        bytes: The hash of an empty root node.
    """
        return self.new().digest()

    def hash_leaf(self, leaf):
        """
    Computes the Merkle leaf hash for a given leaf value.

    This method prefixes the leaf value with a domain separation byte (`RFC6962_LEAF_HASH_PREFIX`)
    and then computes its hash.

    Parameters:
        leaf (bytes): The byte representation of the leaf value to be hashed.

    Returns:
        bytes: The hash of the leaf node with the domain separation prefix.
    """
        h = self.new()
        h.update(bytes([RFC6962_LEAF_HASH_PREFIX]))
        h.update(leaf)
        return h.digest()

    def hash_children(self, leaf, root):
        """
    Computes the Merkle node hash for two child nodes (leaf and root).

    This method prefixes the concatenated leaf and root values with a domain separation byte
    (`RFC6962_NODE_HASH_PREFIX`) and then computes their hash.

    Parameters:
        leaf (bytes): The byte representation of the left child node.
        root (bytes): The byte representation of the right child node.

    Returns:
        bytes: The hash of the two child nodes with the domain separation prefix.
        """
        h = self.new()
        b = bytes([RFC6962_NODE_HASH_PREFIX]) + leaf + root
        h.update(b)
        return h.digest()

    def size(self):
        """
    Returns the size (in bytes) of the digest produced by the hash function.

    This is useful for verifying the length of hashes and 
    for consistency checks in Merkle tree proofs.

    Returns:
        int: The size of the hash function's digest (e.g., 32 for SHA256).
        """
        return self.new().digest_size


# DefaultHasher is a SHA256 based LogHasher
DefaultHasher = Hasher(hashlib.sha256)


def verify_consistency(hasher, checkpoint1: Checkpoint, checkpoint2: Checkpoint, proof):
    """
    Verifies the consistency between two checkpoints in a Merkle tree using a consistency proof.

    Parameters:
        hasher (Hasher): An instance of the Hasher class to compute hashes.
        checkpoint1 (Checkpoint): The first checkpoint, including size and root.
        checkpoint2 (Checkpoint): The second checkpoint, including size and root.
        proof (list of str): A list of hashes (as hex strings) constituting the consistency proof.

    Raises:
        ValueError: If the proof is invalid, or sizes are inconsistent.
        RootMismatchError: If the calculated root does not match the expected root.
    """
    # Change the arguments root1 and root2 to use the attributes from Checkpoint
    root1_bytes = bytes.fromhex(checkpoint1.root)
    root2_bytes = bytes.fromhex(checkpoint2.root)
    bytearray_proof = [bytes.fromhex(elem) for elem in proof]

    # Validate sizes and proof
    if checkpoint2.size < checkpoint1.size:
        raise ValueError(f"size2 ({checkpoint2.size}) < size1 ({checkpoint1.size})")
    if checkpoint1.size == checkpoint2.size:
        if bytearray_proof:
            raise ValueError("size1=size2, but bytearray_proof is not empty")
        verify_match(root1_bytes, root2_bytes)
        return
    if checkpoint1.size == 0:
        if bytearray_proof:
            raise ValueError(f"expected empty bytearray_proof, but{len(bytearray_proof)}")
        return
    if not bytearray_proof:
        raise ValueError("empty bytearray_proof")

    # Decompose the proof
    inner, border = decomp_incl_proof(checkpoint1.size - 1, checkpoint2.size)
    shift = (checkpoint1.size & -checkpoint1.size).bit_length() - 1
    inner -= shift

    # Seed calculation logic
    if checkpoint1.size == 1 << shift:
        seed, start = root1_bytes, 0
    else:
        seed, start = bytearray_proof[0], 1

    if len(bytearray_proof) != start + inner + border:
        raise ValueError(
            f"wrong bytearray_proof size {len(bytearray_proof)}, "
            f"expected {start + inner + border}"
)

    bytearray_proof = bytearray_proof[start:]

    mask = (checkpoint1.size - 1) >> shift
    hash1 = chain_inner_right(hasher, seed, bytearray_proof[:inner], mask)
    hash1 = chain_border_right(hasher, hash1, bytearray_proof[inner:])
    verify_match(hash1, root1_bytes)

    hash2 = chain_inner(hasher, seed, bytearray_proof[:inner], mask)
    hash2 = chain_border_right(hasher, hash2, bytearray_proof[inner:])
    verify_match(hash2, root2_bytes)

def verify_match(calculated, expected):
    """
    Verifies if the calculated root matches the expected root.

    Parameters:
        calculated (bytes): The calculated root hash.
        expected (bytes): The expected root hash.

    Raises:
        RootMismatchError: If the calculated root does not match the expected root.
    """
    if calculated != expected:
        raise RootMismatchError(expected, calculated)


def decomp_incl_proof(index, size):
    """
    Decomposes the inclusion proof into inner and border proof components.

    Parameters:
        index (int): The index of the leaf node in the Merkle tree.
        size (int): The total size of the Merkle tree.

    Returns:
        tuple: A tuple (inner, border), where inner is the size of the inner proof and
               border is the size of the border proof.
    """
    inner = inner_proof_size(index, size)
    border = bin(index >> inner).count("1")
    return inner, border


def inner_proof_size(index, size):
    """
    Computes the size of the inner proof based on the index and size.

    Parameters:
        index (int): The index of the leaf node in the Merkle tree.
        size (int): The total size of the Merkle tree.

    Returns:
        int: The size of the inner proof.
    """
    return (index ^ (size - 1)).bit_length()


def chain_inner(hasher, seed, proof, index):
    """
    Computes the inner proof hash chain.

    Parameters:
        hasher (Hasher): An instance of the Hasher class to compute hashes.
        seed (bytes): The starting hash (usually the leaf hash).
        proof (list of bytes): The hashes in the proof.
        index (int): The index of the leaf in the Merkle tree.

    Returns:
        bytes: The resulting hash after processing the inner proof.
    """
    for i, h in enumerate(proof):
        if (index >> i) & 1 == 0:
            seed = hasher.hash_children(seed, h)
        else:
            seed = hasher.hash_children(h, seed)
    return seed


def chain_inner_right(hasher, seed, proof, index):
    """
    Computes the inner proof hash chain for right children.

    Parameters:
        hasher (Hasher): An instance of the Hasher class to compute hashes.
        seed (bytes): The starting hash.
        proof (list of bytes): The hashes in the proof.
        index (int): The index of the leaf in the Merkle tree.

    Returns:
        bytes: The resulting hash after processing the right inner proof.
    """
    for i, h in enumerate(proof):
        if (index >> i) & 1 == 1:
            seed = hasher.hash_children(h, seed)
    return seed


def chain_border_right(hasher, seed, proof):
    """
    Computes the border proof hash chain for a Merkle tree.

    Parameters:
        hasher (Hasher): An instance of the Hasher class to compute hashes.
        seed (bytes): The starting hash.
        proof (list of bytes): The hashes in the proof.

    Returns:
        bytes: The resulting hash after processing the border proof.
    """
    for h in proof:
        seed = hasher.hash_children(h, seed)
    return seed


class RootMismatchError(Exception):
    """
    Exception raised when the calculated root hash does not match the expected root hash.

    Attributes:
        expected_root (str): The expected root hash (in hex format).
        calculated_root (str): The calculated root hash (in hex format).
    """
    def __init__(self, expected_root, calculated_root):
        self.expected_root = binascii.hexlify(bytearray(expected_root))
        self.calculated_root = binascii.hexlify(bytearray(calculated_root))

    def __str__(self):
        return (
    f"calculated root:\n{self.calculated_root}\n"
    f"does not match expected root:\n{self.expected_root}"
)


def root_from_inclusion_proof(hasher, index, size, leaf_hash, proof):
    """
    Computes the root hash of the Merkle tree from an inclusion proof.

    Parameters:
        hasher (Hasher): An instance of the Hasher class to compute hashes.
        index (int): The index of the leaf node in the Merkle tree.
        size (int): The total size of the Merkle tree.
        leaf_hash (bytes): The hash of the leaf node.
        proof (list of bytes): The inclusion proof hashes.

    Returns:
        bytes: The calculated root hash.

    Raises:
        ValueError: If the proof or leaf hash is invalid.
    """
    if index >= size:
        raise ValueError(f"index is beyond size: {index} >= {size}")

    if len(leaf_hash) != hasher.size():
        raise ValueError(
            f"leaf_hash has unexpected size {len(leaf_hash)}, want {hasher.size()}"
        )

    inner, border = decomp_incl_proof(index, size)
    if len(proof) != inner + border:
        raise ValueError(f"wrong proof size {len(proof)}, want {inner + border}")

    res = chain_inner(hasher, leaf_hash, proof[:inner], index)
    res = chain_border_right(hasher, res, proof[inner:])
    return res


def verify_inclusion(hasher, inclusion_proof: InclusionProof, debug=False):
    """
    Verifies the inclusion of a leaf in the Merkle tree using the inclusion proof.

    Parameters:
        hasher (Hasher): An instance of the Hasher class to compute hashes.
        inclusion_proof (InclusionProof): An object containing the proof information.
        debug (bool): If True, prints debug information.

    Raises:
        RootMismatchError: If the calculated root does not match the expected root.
    """
    bytearray_proof = [bytes.fromhex(elem) for elem in inclusion_proof.proof]
    bytearray_root = bytes.fromhex(inclusion_proof.root)
    bytearray_leaf = bytes.fromhex(inclusion_proof.leaf_hash)

    # Calculate the root from the inclusion proof
    calc_root = root_from_inclusion_proof(
        hasher, inclusion_proof.index, inclusion_proof.size, bytearray_leaf, bytearray_proof
    )
    # Verify if the calculated root matches the expected root
    verify_match(calc_root, bytearray_root)
    # Print debug information if required
    if debug:
        print("Calculated root hash", calc_root.hex())
        print("Given root hash", bytearray_root.hex())

# requires entry["body"] output for a log entry
# returns the leaf hash according to the rfc 6962 spec
def compute_leaf_hash(body):
    """
    Computes the leaf hash for a log entry according to RFC 6962.

    Parameters:
        body (str): The base64-encoded body of the log entry.

    Returns:
        str: The computed leaf hash (as a hex string).
    """
    entry_bytes = base64.b64decode(body)

    # create a new sha256 hash object
    h = hashlib.sha256()
    # write the leaf hash prefix
    h.update(bytes([RFC6962_LEAF_HASH_PREFIX]))

    # write the actual leaf data
    h.update(entry_bytes)

    # return the computed hash
    return h.hexdigest()
