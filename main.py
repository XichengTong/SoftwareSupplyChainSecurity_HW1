import argparse
import base64
import json
import os
import requests
REKOR_API_URL = "https://rekor.sigstore.dev"
from util import extract_public_key, verify_artifact_signature
from merkle_proof import DefaultHasher, verify_consistency, verify_inclusion, compute_leaf_hash

def get_log_entry(log_index, debug=False):
    """
    Fetches a log entry from the Rekor transparency log by log index,
    decodes the body field to extract the signature and public key.
    
    Parameters:
        log_index (int): The index of the log entry to fetch.
        debug (bool): If True, additional debug information will be printed.
    
    Returns:
        dict: A dictionary containing the decoded signature and public key, or None if an error occurs.
    """
    # Step 1: Construct the API URL to fetch the log entry by log index
    log_entry_url = f"{REKOR_API_URL}/api/v1/log/entries?logIndex={log_index}"
    
    try:
        # Step 2: Make the GET request to fetch the log entry
        response = requests.get(log_entry_url)
        
        # Step 3: Check if the request was successful
        if response.status_code == 200:
            log_entry = response.json()

            if debug:
                print(f"Log entry fetched successfully: {log_entry}")
            
            # Step 4: Access the entry's body and decode it from base64
            entry_data = next(iter(log_entry.values()))
            body_base64 = entry_data.get('body')

            if body_base64:
                decoded_body = base64.b64decode(body_base64).decode('utf-8')

                if debug:
                    print(f"Decoded body: {decoded_body}")
                
                # Step 5: Parse the decoded body as JSON
                body_json = json.loads(decoded_body)
                
                # Step 6: Extract the signature and public key from the JSON data
                signature = body_json.get("spec", {}).get("signature", {}).get("content")
                public_key = body_json.get("spec", {}).get("signature", {}).get("publicKey", {}).get("content")
                
                if signature and public_key:
                    if debug:
                        print(f"Extracted signature: {signature}")
                        print(f"Extracted public key: {public_key}")
                    
                    # Return the signature and public key
                    return {
                        "signature": signature,
                        "public_key": public_key
                    }
                else:
                    if debug:
                        print("Signature or public key not found in the decoded body.")
                    return None
            else:
                if debug:
                    print("Body field is missing or empty.")
                return None
        else:
            if debug:
                print(f"Failed to fetch log entry. Status code: {response.status_code}")
            return None
    except requests.exceptions.RequestException as e:
        if debug:
            print(f"Error while fetching log entry: {e}")
        return None
    
def get_verification_proof(log_index, debug=False):
    """
    Fetches the log entry from Rekor, calculates the leaf hash using compute_leaf_hash,
    and returns all necessary information for verifying inclusion (index, tree_size, leaf_hash, etc.).
    
    Parameters:
        log_index (int): The index of the log entry to fetch.
        debug (bool): If True, additional debug information will be printed.
    
    Returns:
        dict: A dictionary containing the index, tree_size, hashes, root_hash, and leaf_hash.
    """
    # Step 1: Validate log index
    if not isinstance(log_index, int) or log_index < 0:
        raise ValueError("Log index must be a non-negative integer.")
    
    if debug:
        print(f"Fetching log entry for log index: {log_index}")
    
    # Step 2: Fetch the log entry using the log index
    log_entry_url = f"{REKOR_API_URL}/api/v1/log/entries?logIndex={log_index}"
    
    try:
        response = requests.get(log_entry_url)
        if response.status_code == 200:
            log_entry = response.json()
            entryUUID = next(iter(log_entry.keys()))  # Extract the entryUUID (key in the response)

            if debug:
                print(f"Log entry fetched successfully: {log_entry}")
            
            # Step 3: Access the entry's body (base64-encoded) directly
            entry_data = log_entry[entryUUID]
            body_base64 = entry_data.get('body')

            if body_base64:
                # Step 4: Compute the leaf hash directly using compute_leaf_hash
                leaf_hash = compute_leaf_hash(body_base64)  # No manual base64 decoding
                
                if debug:
                    print(f"Calculated leaf hash: {leaf_hash}")
                
                # Step 5: Extract inclusion proof data (index, tree_size, root_hash, and hashes) from log entry
                inclusion_proof = entry_data.get("verification", {}).get("inclusionProof", {})
                
                tree_size = inclusion_proof.get("treeSize")
                index = inclusion_proof.get("logIndex")
                root_hash = inclusion_proof.get("rootHash")
                hashes = inclusion_proof.get("hashes")
                
                if debug:
                    print(f"Inclusion proof details: Index: {index}, Tree Size: {tree_size}, Root Hash: {root_hash}, Hashes: {hashes}")
                
                return {
                    "leaf_hash": leaf_hash,
                    "index": index,
                    "tree_size": tree_size,
                    "root_hash": root_hash,
                    "hashes": hashes
                }
            else:
                if debug:
                    print("Body field is missing or empty.")
                return None
        else:
            if debug:
                print(f"Failed to fetch log entry. Status code: {response.status_code}")
            return None
    except requests.exceptions.RequestException as e:
        if debug:
            print(f"Error while fetching log entry: {e}")
        return None

def inclusion(log_index, artifact_filepath, debug=False):
    """
    Verifies that the log entry is included in the Rekor transparency log and the artifact signature is valid.
    
    Parameters:
        log_index (int): The index of the log entry to verify.
        artifact_filepath (str): The path to the artifact file.
        debug (bool): If True, print additional debug information.
    
    Returns:
        bool: True if the inclusion proof and artifact signature are valid, False otherwise.
    """
    # Step 1: Verify the log index and artifact file path
    if not isinstance(log_index, int) or log_index < 0:
        raise ValueError("Log index must be a non-negative integer.")
    
    if not os.path.exists(artifact_filepath):
        raise ValueError(f"Artifact file {artifact_filepath} does not exist.")
    
    if debug:
        print(f"Verifying log index: {log_index} and artifact: {artifact_filepath}")
    
    # Step 2: Fetch the log entry and extract the certificate and signature
    log_entry_data = get_log_entry(log_index, debug=debug)
    
    if not log_entry_data:
        if debug:
            print("Failed to fetch the log entry.")
        return False
    
    certificate = log_entry_data.get("public_key")
    signature = log_entry_data.get("signature")
    
    if not certificate or not signature:
        if debug:
            print("Certificate or signature is missing in the log entry.")
        return False
    
    # Step 3: Extract the public key from the certificate
    public_key = extract_public_key(certificate)
    
    if not public_key:
        if debug:
            print("Failed to extract public key from the certificate.")
        return False
    
    # Step 4: Verify the artifact's signature
    if not verify_artifact_signature(signature, public_key, artifact_filepath):
        if debug:
            print("Artifact signature verification failed.")
        return False
    
    if debug:
        print("Artifact signature verified successfully.")
    
    # Step 5: Get the inclusion proof and leaf hash
    proof_data = get_verification_proof(log_index, debug=debug)
    
    if not proof_data:
        if debug:
            print("Failed to fetch the inclusion proof.")
        return False
    
    leaf_hash = proof_data.get("leaf_hash")
    index = proof_data.get("index")
    tree_size = proof_data.get("tree_size")
    root_hash = proof_data.get("root_hash")
    hashes = proof_data.get("hashes")
    
    if not (leaf_hash and index and tree_size and root_hash and hashes):
        if debug:
            print("Incomplete inclusion proof data.")
        return False
    
    # Step 6: Verify the inclusion proof using the Merkle tree proof
    if verify_inclusion(DefaultHasher(), index, tree_size, leaf_hash, hashes, root_hash):
        if debug:
            print("Inclusion proof verified successfully.")
        return True
    else:
        if debug:
            print("Inclusion proof verification failed.")
        return False

def get_latest_checkpoint(debug=False):
    pass

def consistency(prev_checkpoint, debug=False):
    # verify that prev checkpoint is not empty
    # get_latest_checkpoint()
    pass

def main():
    debug = False
    parser = argparse.ArgumentParser(description="Rekor Verifier")
    parser.add_argument('-d', '--debug', help='Debug mode',
                        required=False, action='store_true') # Default false
    parser.add_argument('-c', '--checkpoint', help='Obtain latest checkpoint\
                        from Rekor Server public instance',
                        required=False, action='store_true')
    parser.add_argument('--inclusion', help='Verify inclusion of an\
                        entry in the Rekor Transparency Log using log index\
                        and artifact filename.\
                        Usage: --inclusion 126574567',
                        required=False, type=int)
    parser.add_argument('--artifact', help='Artifact filepath for verifying\
                        signature',
                        required=False)
    parser.add_argument('--consistency', help='Verify consistency of a given\
                        checkpoint with the latest checkpoint.',
                        action='store_true')
    parser.add_argument('--tree-id', help='Tree ID for consistency proof',
                        required=False)
    parser.add_argument('--tree-size', help='Tree size for consistency proof',
                        required=False, type=int)
    parser.add_argument('--root-hash', help='Root hash for consistency proof',
                        required=False)
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
