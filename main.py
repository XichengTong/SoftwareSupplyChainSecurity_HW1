import argparse
import requests;
from util import extract_public_key, verify_artifact_signature
from merkle_proof import DefaultHasher, verify_consistency, verify_inclusion, compute_leaf_hash

def get_log_entry(log_index, debug=False):
    """
    Fetches a log entry from the Rekor transparency log based on the log index.
    
    Parameters:
        log_index (int): The index of the log entry to fetch.
        debug (bool): If True, additional debug information will be printed.
    
    Returns:
        dict: The log entry details if found, otherwise None.
    """
    # Step 1: Verify that log index is sane
    if not isinstance(log_index, int) or log_index < 0:
        raise ValueError("Log index must be a non-negative integer.")
    
    if debug:
        print(f"Fetching log entry for log index: {log_index}")
    
    # Step 2: Construct the API URL to fetch the log entry
    log_entry_url = f"{REKOR_API_URL}/api/v1/log/entries?logIndex={log_index}"
    
    try:
        # Step 3: Make the request to the Rekor API
        response = requests.get(log_entry_url)
        
        # Step 4: Check if the request was successful
        if response.status_code == 200:
            log_entry = response.json()
            
            if debug:
                print(f"Log entry fetched successfully: {log_entry}")
            
            return log_entry
        else:
            if debug:
                print(f"Failed to fetch log entry. Status code: {response.status_code}")
            return None
    except requests.exceptions.RequestException as e:
        if debug:
            print(f"Error while fetching log entry: {e}")
        return None
    
def get_verification_proof(log_index, debug=False):
    # verify that log index value is sane
    pass

def inclusion(log_index, artifact_filepath, debug=False):
    # verify that log index and artifact filepath values are sane
    # extract_public_key(certificate)
    # verify_artifact_signature(signature, public_key, artifact_filepath)
    # get_verification_proof(log_index)
    # verify_inclusion(DefaultHasher, index, tree_size, leaf_hash, hashes, root_hash)
    pass

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
