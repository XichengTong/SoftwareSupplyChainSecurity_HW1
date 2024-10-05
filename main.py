"""
Rekor Verifier - A command-line tool for verifying entries in the Rekor transparency log.

This script provides functionality to:
    - Fetch and print the latest checkpoint from the Rekor public log server.
    - Verify the inclusion of an artifact in the Rekor transparency log.
    - Verify consistency between two checkpoints of the log.

Command-Line Arguments:
    -d, --debug:
        Enables debug mode, printing additional information.

    -c, --checkpoint:
        Fetches the latest checkpoint from the Rekor server and prints it.

    --inclusion <logIndex>:
        Verifies the inclusion of an entry in the Rekor log 
        using the provided log index and artifact file.

    --artifact <filepath>:
        The file path of the artifact used for signature verification in inclusion verification.

    --consistency:
        Verifies the consistency between a previous checkpoint and the latest checkpoint.

    --tree-id <treeID>:
        The Tree ID for the previous checkpoint. Required if verifying consistency.

    --tree-size <size>:
        The size of the Merkle tree for the previous checkpoint. Required if verifying consistency.

    --root-hash <hash>:
        The root hash for the previous checkpoint. Required if verifying consistency.

Modules:
    - requests: For making HTTP requests to the Rekor API.
    - argparse: For parsing command-line arguments.
    - base64, json, hashlib: For encoding, decoding, and cryptographic operations.
    - util and merkle_proof: Utility functions for signature 
    verification and Merkle tree proof verification.
"""
import argparse
import base64
import json
import os
from dataclasses import dataclass
import requests
from util import extract_public_key, verify_artifact_signature
from merkle_proof import (
    DefaultHasher,
    verify_consistency,
    verify_inclusion,
    InclusionProof,
    compute_leaf_hash,
)

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


def validate_log_index(log_index):
    """
    Validates the provided log index to ensure it is a non-negative integer.

    This function checks if the log index is an integer and if it is
    greater than or equal to 0. If the log index fails either condition,
    it raises a ValueError with an appropriate message.

    Parameters:
        log_index (int): The log index to validate.

    Raises:
        ValueError: If the log index is not an integer or is negative.
    """
    if not isinstance(log_index, int) or log_index < 0:
        raise ValueError("Log index must be a non-negative integer.")


def get_log_entry_url(log_index):
    """
    Constructs the log entry URL based on the log index provided.

    Parameters:
        log_index (int): The index of the log entry to fetch.

    Returns:
        str: The constructed URL for fetching the log entry.
    """
    # Fetch the rekor_api_url from environment variables or use the default URL
    rekor_api_url = os.getenv("rekor_api_url", "https://rekor.sigstore.dev")

    # Construct and return the log entry URL
    return f"{rekor_api_url}/api/v1/log/entries?logIndex={log_index}"


def get_log_entry(log_index, debug=False):
    """
    Fetches a log entry from the Rekor transparency log by log index,
    decodes the body field to extract the signature and public key.

    Parameters:
        log_index (int): The index of the log entry to fetch.
        debug (bool): If True, additional debug information will be printed.

    Returns:
        dict: A dictionary containing the decoded signature and public key,
          or None if an error occurs.
    """
    # Construct the API URL to fetch the log entry by log index
    log_entry_url = get_log_entry_url(log_index)

    try:
        # Make the GET request to fetch the log entry
        response = requests.get(log_entry_url, timeout=10)

        # Check if the request was successful
        if response.status_code != 200:
            if debug:
                print(f"Failed to fetch log entry. Status code: {response.status_code}")
            return None

        log_entry = response.json()

        # Access the entry's body and decode it from base64
        entry_data = next(iter(log_entry.values()))
        body_base64 = entry_data.get("body")

        if body_base64:
            decoded_body = base64.b64decode(body_base64).decode("utf-8")

            if debug:
                print(f"Decoded body: {decoded_body}")

            # Parse the decoded body as JSON
            body_json = json.loads(decoded_body)

            # Extract the signature and public key from the JSON data
            signature = body_json.get("spec", {}).get("signature", {}).get("content")
            public_key = (
                body_json.get("spec", {})
                .get("signature", {})
                .get("publicKey", {})
                .get("content")
            )

            if signature and public_key:
                if debug:
                    print(f"Extracted signature: {signature}")
                    print(f"Extracted public key: {public_key}")

                # Return the signature and public key as PyBytes
                return {"signature": signature, "public_key": public_key}
            if debug:
                print("Signature or public key not found in the decoded body.")
            return None
        if debug:
            print("Body field is missing or empty.")
        return None
    except requests.exceptions.RequestException as e:
        if debug:
            print(f"Error while fetching log entry: {e}")
        return None


def get_verification_proof(log_index, debug=False):
    """
    Fetches the log entry from Rekor, calculates the leaf hash using compute_leaf_hash,
    and returns all necessary information for verifying inclusion
    (index, tree_size, leaf_hash, etc.).
    Parameters:
        log_index (int): The index of the log entry to fetch.
        debug (bool): If True, additional debug information will be printed.

    Returns:
        dict: A dictionary containing the index, tree_size, hashes, root_hash, and leaf_hash.
    """
    # Validate log index
    validate_log_index(log_index)

    if debug:
        print(f"Fetching log entry for log index: {log_index}")

    # Fetch the log entry using the log index
    log_entry_url = get_log_entry_url(log_index)

    try:
        response = requests.get(log_entry_url, timeout=10)
        if response.status_code == 200:
            log_entry = response.json()
            entry_uuid = next(iter(log_entry.keys()))  # Extract the entry_uuid

            if debug:
                print(f"Log entry fetched successfully: {log_entry}")

            # Access the entry's body
            entry_data = log_entry[entry_uuid]
            body_base64 = entry_data.get("body")

            if body_base64:
                # Compute the leaf hash directly using compute_leaf_hash
                leaf_hash = compute_leaf_hash(body_base64)

                if debug:
                    print(f"Calculated leaf hash: {leaf_hash}")

                # Extract inclusion proof data (index, tree_size, root_hash, and hashes)
                #  from log entry
                inclusion_proof = entry_data.get("verification", {}).get(
                    "inclusionProof", {}
                )

                tree_size = inclusion_proof.get("treeSize")
                index = inclusion_proof.get("logIndex")
                root_hash = inclusion_proof.get("rootHash")
                hashes = inclusion_proof.get("hashes")

                if debug:
                    print(
                        f"Inclusion proof details:{index},{tree_size},{root_hash},{hashes}"
                    )

                return {
                    "leaf_hash": leaf_hash,
                    "index": index,
                    "tree_size": tree_size,
                    "root_hash": root_hash,
                    "hashes": hashes,
                }
            if debug:
                print("Body field is missing or empty.")
            return None
        if debug:
            print(f"Failed to fetch log entry. Status code: {response.status_code}")
        return None
    except requests.exceptions.RequestException as e:
        if debug:
            print(f"Error while fetching log entry: {e}")
        return None


def inclusion(log_index, artifact_filepath, debug=False):
    """
    Verifies that the log entry is included in the 
    Rekor transparency log and the artifact signature is valid.

    Parameters:
        log_index (int): The index of the log entry to verify.
        artifact_filepath (str): The path to the artifact file.
        debug (bool): If True, print additional debug information.

    Returns:
        bool: True if the inclusion proof and artifact signature are valid, False otherwise.
    """
    # Verify the log index and artifact file path
    validate_log_index(log_index)

    if not os.path.exists(artifact_filepath):
        raise ValueError(f"Artifact file {artifact_filepath} does not exist.")

    # SFetch the log entry and extract the public key and signature
    log_entry_data = get_log_entry(log_index, debug=debug)

    public_key = log_entry_data.get("public_key")
    signature = log_entry_data.get("signature")

    # Extract the public key (directly from PEM-formatted string)
    public_key_decode = extract_public_key(
        base64.b64decode(public_key)
    )  # Pass the PEM-formatted public key as bytes

    if not public_key_decode or not public_key or not signature or not log_entry_data:
        return False

    # Verify the artifact's signature
    if verify_artifact_signature(
        base64.b64decode(signature), public_key_decode, artifact_filepath
    ):
        return False

    print("Signature is Valid.")

    # Get the inclusion proof and leaf hash
    proof_data = get_verification_proof(log_index, debug=debug)

    if not proof_data:
        return False

    leaf_hash = proof_data.get("leaf_hash")
    index = proof_data.get("index")
    tree_size = proof_data.get("tree_size")
    root_hash = proof_data.get("root_hash")
    hashes = proof_data.get("hashes")

    if not (leaf_hash and index and tree_size and root_hash and hashes):
        return False
    # Create an InclusionProof object
    inclusion_proof = InclusionProof(
    index=index,
    size=tree_size,
    leaf_hash=leaf_hash,
    proof=hashes,
    root=root_hash
)
    # Verify the inclusion proof using the Merkle tree proof
    if not verify_inclusion(DefaultHasher, inclusion_proof):
        print("Offline root hash calculation for inclusion verified.")
        return True
    return None



def get_latest_checkpoint(debug=False):
    """
    Fetch the latest checkpoint from the Rekor transparency log.

    This function sends a GET request to the Rekor API to retrieve the most
    recent checkpoint, which contains metadata about the current state of
    the transparency log, such as the tree size, root hash, and other details.

    Parameters:
        debug (bool): If True, additional debug information is printed.

    Returns:
        dict or None: A dictionary representing the latest checkpoint if
                      the request is successful, None otherwise.
    """

    # Fetch the rekor_api_url from environment variables or use the default URL
    rekor_api_url = os.getenv("rekor_api_url", "https://rekor.sigstore.dev")

    url = f"{rekor_api_url}/api/v1/log"
    try:
        response = requests.get(url,timeout=10)
        if response.status_code == 200:
            latest_checkpoint = response.json()
            if debug:
                print(f"Latest checkpoint fetched successfully: {latest_checkpoint}")
            # print(latest_checkpoint)
            return latest_checkpoint
        if debug:
            print(
                f"Failed to fetch the latest checkpoint. Status code: {response.status_code}"
            )
    except requests.exceptions.RequestException as e:
        if debug:
            print(f"Error while fetching the latest checkpoint: {e}")
    return None


def consistency(prev_checkpoint, debug=False):
    """
    Verify consistency between a previous checkpoint and the latest checkpoint.

    This function checks whether the state of the transparency log has evolved
    in a consistent manner between two points in time. It does this by:
    1. Fetching the latest checkpoint from the Rekor log.
    2. Requesting a consistency proof from the Rekor API using the previous
       and latest tree sizes.
    3. Verifying the consistency proof using the previous and latest root hashes.

    Parameters:
        prev_checkpoint (dict): The previous checkpoint containing details
                                'treeID', 'treeSize', and 'rootHash'.
        debug (bool): If True, additional debug information is printed.

    Returns:
        bool: True if the consistency proof is valid and the logs are consistent,
              False otherwise.
    """
    if not prev_checkpoint or not all(
        k in prev_checkpoint for k in ["treeID", "treeSize", "rootHash"]
    ):
        if debug:
            print("Previous checkpoint details are incomplete.")
        return False

    latest_checkpoint = get_latest_checkpoint(debug)
    if not latest_checkpoint:
        return False

    # Extract necessary details from the latest checkpoint
    latest_tree_size = latest_checkpoint.get("treeSize", 0)
    tree_id = latest_checkpoint.get("treeID")

    # Fetch the rekor_api_url from environment variables or use the default URL
    rekor_api_url = os.getenv("rekor_api_url", "https://rekor.sigstore.dev")

    # Fetch the consistency proof from Rekor
    url = f"{rekor_api_url}/api/v1/log/proof"
    params = {
        "firstSize": prev_checkpoint["treeSize"],
        "lastSize": latest_tree_size,
        "treeID": tree_id,
    }

    try:
        response = requests.get(url, params=params, timeout=10)
        if response.status_code == 200:
            proof_data = response.json()
            hashes = proof_data.get("hashes", [])
            prev_cp = Checkpoint(
                size=prev_checkpoint["treeSize"],
                root=prev_checkpoint["rootHash"]
)

            latest_cp = Checkpoint(
                size=latest_tree_size,
                root=latest_checkpoint["rootHash"]
)
            if not verify_consistency(
                DefaultHasher,
                prev_cp,
                latest_cp,
                hashes
            ):
                print("Consistency verification successful.")
                return True
            print("Consistency verification failed.")
            return False
        if debug:
            print(
                f"Failed to fetch consistency proof. Status code: {response.status_code}"
            )
        return False
    except requests.exceptions.RequestException as e:
        if debug:
            print(f"Error while fetching consistency proof: {e}")
        return False

def main():
    """
    Main entry point for the Rekor Verifier command-line tool.

    This function parses the command-line arguments, which determine the actions
    that the tool will perform, such as fetching the latest checkpoint, verifying
    inclusion of an entry in the Rekor Transparency Log, or verifying consistency
    between two checkpoints.

    Command-line Arguments:
        -d, --debug:
            Optional flag to enable debug mode. Prints additional debug information.

        -c, --checkpoint:
            Optional flag to fetch and print the latest checkpoint from the Rekor
            server's public instance. If debug mode is enabled, the checkpoint will
            be stored in a file named 'checkpoint.json'.

        --inclusion <logIndex>:
            Verify the inclusion of an entry in the Rekor Transparency Log using the
            specified log index and artifact filename.

        --artifact <filepath>:
            The file path of the artifact used for signature verification when checking
            inclusion. This argument is used in conjunction with the --inclusion option.

        --consistency:
            Optional flag to verify the consistency of a given checkpoint with the
            latest checkpoint from the Rekor server.

        --tree-id <treeID>:
            The Tree ID for the consistency proof verification. Required if --consistency
            is specified.

        --tree-size <size>:
            The Tree size of the previous checkpoint. Required if --consistency is
            specified.

        --root-hash <hash>:
            The Root hash of the previous checkpoint. Required if --consistency is
            specified.

    Workflow:
        - If the --debug flag is used, debug mode is enabled and debug information is printed.
        - If the --checkpoint flag is used, the latest checkpoint is fetched and printed.
        - If the --inclusion option is specified, the inclusion proof of an entry
          is verified using the provided log index and artifact file.
        - If the --consistency option is specified, consistency verification is performed
          using the provided Tree ID, Tree Size, and Root Hash.

    Returns:
        None
    """
    debug = False
    parser = argparse.ArgumentParser(description="Rekor Verifier")
    parser.add_argument(
        "-d", "--debug", help="Debug mode", required=False, action="store_true"
    )  # Default false
    parser.add_argument(
        "-c",
        "--checkpoint",
        help="Obtain latest checkpoint\
                        from Rekor Server public instance",
        required=False,
        action="store_true",
    )
    parser.add_argument(
        "--inclusion",
        help="Verify inclusion of an\
                        entry in the Rekor Transparency Log using log index\
                        and artifact filename.\
                        Usage: --inclusion 126574567",
        required=False,
        type=int,
    )
    parser.add_argument(
        "--artifact",
        help="Artifact filepath for verifying\
                        signature",
        required=False,
    )
    parser.add_argument(
        "--consistency",
        help="Verify consistency of a given\
                        checkpoint with the latest checkpoint.",
        action="store_true",
    )
    parser.add_argument(
        "--tree-id", help="Tree ID for consistency proof", required=False
    )
    parser.add_argument(
        "--tree-size", help="Tree size for consistency proof", required=False, type=int
    )
    parser.add_argument(
        "--root-hash", help="Root hash for consistency proof", required=False
    )
    args = parser.parse_args()
    if args.debug:
        debug = True
        print("enabled debug mode")
    if args.checkpoint:
        # get and print latest checkpoint from server
        # if debug is enabled, store it in a file checkpoint.json
        checkpoint = get_latest_checkpoint(debug)
        print(json.dumps(checkpoint, indent=4))
    if args.inclusion:
        inclusion(args.inclusion, args.artifact, debug)
    if args.consistency:
        if not args.tree_id:
            print("please specify tree id for prev checkpoint")
            return
        if not args.tree_size:
            print("please specify tree size for prev checkpoint")
            return
        if not args.root_hash:
            print("please specify root hash for prev checkpoint")
            return

        prev_checkpoint = {}
        prev_checkpoint["treeID"] = args.tree_id
        prev_checkpoint["treeSize"] = args.tree_size
        prev_checkpoint["rootHash"] = args.root_hash

        consistency(prev_checkpoint, debug)


if __name__ == "__main__":
    main()
