import argparse
import base64
import json
import os
import requests
REKOR_API_URL = "https://rekor.sigstore.dev"
from myproject.util import extract_public_key, verify_artifact_signature
from myproject.merkle_proof import (
    DefaultHasher,
    verify_consistency,
    verify_inclusion,
    compute_leaf_hash,
)


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
    # Construct the API URL to fetch the log entry by log index
    log_entry_url = f"{REKOR_API_URL}/api/v1/log/entries?logIndex={log_index}"
    
    try:
        # Make the GET request to fetch the log entry
        response = requests.get(log_entry_url)
        
        # Check if the request was successful
        if response.status_code == 200:
            log_entry = response.json()

            if debug:
                print(f"Log entry fetched successfully: {log_entry}")
            
            # Access the entry's body and decode it from base64
            entry_data = next(iter(log_entry.values()))
            body_base64 = entry_data.get('body')

            if body_base64:
                decoded_body = base64.b64decode(body_base64).decode('utf-8')

                if debug:
                    print(f"Decoded body: {decoded_body}")
                
                # Parse the decoded body as JSON
                body_json = json.loads(decoded_body)
                
                # Extract the signature and public key from the JSON data
                signature = body_json.get("spec", {}).get("signature", {}).get("content")
                public_key = body_json.get("spec", {}).get("signature", {}).get("publicKey", {}).get("content")
                
                
                if signature and public_key:
                    if debug:
                        print(f"Extracted signature: {signature}")
                        print(f"Extracted public key: {public_key}")
                    
                   
                    # Return the signature and public key as PyBytes
                    return {
                        "signature": signature,
                        "public_key": public_key  
                    }
               
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
    # Validate log index
    if not isinstance(log_index, int) or log_index < 0:
        raise ValueError("Log index must be a non-negative integer.")
    
    if debug:
        print(f"Fetching log entry for log index: {log_index}")
    
    # Fetch the log entry using the log index
    log_entry_url = f"{REKOR_API_URL}/api/v1/log/entries?logIndex={log_index}"
    
    try:
        response = requests.get(log_entry_url)
        if response.status_code == 200:
            log_entry = response.json()
            entryUUID = next(iter(log_entry.keys()))  # Extract the entryUUID

            if debug:
                print(f"Log entry fetched successfully: {log_entry}")
            
            # Access the entry's body
            entry_data = log_entry[entryUUID]
            body_base64 = entry_data.get('body')

            if body_base64:
                # Compute the leaf hash directly using compute_leaf_hash
                leaf_hash = compute_leaf_hash(body_base64)  
                
                if debug:
                    print(f"Calculated leaf hash: {leaf_hash}")
                
                # Extract inclusion proof data (index, tree_size, root_hash, and hashes) from log entry
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
    # Verify the log index and artifact file path
    if not isinstance(log_index, int) or log_index < 0:
        raise ValueError("Log index must be a non-negative integer.")
    
    if not os.path.exists(artifact_filepath):
        raise ValueError(f"Artifact file {artifact_filepath} does not exist.")
    
    if debug:
        print(f"Verifying log index: {log_index} and artifact: {artifact_filepath}")
    
    # SFetch the log entry and extract the public key and signature
    log_entry_data = get_log_entry(log_index, debug=debug)
    
    if not log_entry_data:
        if debug:
            print("Failed to fetch the log entry.")
        return False
    
    public_key = log_entry_data.get("public_key")
    signature = log_entry_data.get("signature")
    
    
    if not public_key or not signature:
        if debug:
            print("Public key or signature is missing in the log entry.")
        return False
    
    # Extract the public key (directly from PEM-formatted string)
    public_key_decode = extract_public_key(base64.b64decode(public_key))  # Pass the PEM-formatted public key as bytes
    
    if not public_key_decode:
        if debug:
            print("Failed to extract public key from the PEM-formatted public key.")
        return False
    
    # Verify the artifact's signature
    if verify_artifact_signature(base64.b64decode(signature), public_key_decode, artifact_filepath):
        if debug:
            print("Artifact signature verification failed.")
        return False
    
    print("Signature is Valid.")
    
    #if debug:
    #    print("Artifact signature verified successfully.")
    
    # Get the inclusion proof and leaf hash
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
    
    # Verify the inclusion proof using the Merkle tree proof
    if not verify_inclusion(DefaultHasher, index, tree_size, leaf_hash, hashes, root_hash):
        print("Offline root hash calculation for inclusion verified.")
        return True
    else:
        if debug:
            print("Inclusion proof verification failed.")
        return False

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
    url = f"{REKOR_API_URL}/api/v1/log"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            latest_checkpoint = response.json()
            if debug:
                print(f"Latest checkpoint fetched successfully: {latest_checkpoint}")
            #print(latest_checkpoint)
            return latest_checkpoint
        else:
            if debug:
                print(f"Failed to fetch the latest checkpoint. Status code: {response.status_code}")
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
    if not prev_checkpoint or not all(k in prev_checkpoint for k in ['treeID', 'treeSize', 'rootHash']):
        if debug:
            print("Previous checkpoint details are incomplete.")
        return False

    latest_checkpoint = get_latest_checkpoint(debug)
    if not latest_checkpoint:
        return False
    
    # Extract necessary details from the latest checkpoint
    latest_tree_size = latest_checkpoint.get('treeSize', 0)
    tree_id = latest_checkpoint.get('treeID')

    # Fetch the consistency proof from Rekor
    url = f"{REKOR_API_URL}/api/v1/log/proof"
    params = {
        'firstSize': prev_checkpoint['treeSize'],
        'lastSize': latest_tree_size,
        'treeID': tree_id
    }
    
    try:
        response = requests.get(url, params=params)
        if response.status_code == 200:
            proof_data = response.json()
            hashes = proof_data.get('hashes', [])
            if not verify_consistency(DefaultHasher, prev_checkpoint['treeSize'], latest_tree_size, hashes, prev_checkpoint['rootHash'], latest_checkpoint['rootHash']): 
                print("Consistency verification successful.")
                return True
            else:
                print("Consistency verification failed.")
                return False
        else:
            if debug:
                print(f"Failed to fetch consistency proof. Status code: {response.status_code}")
            return False
    except requests.exceptions.RequestException as e:
        if debug:
            print(f"Error while fetching consistency proof: {e}")
        return False

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
