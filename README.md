# Project Name: Software Supply Chain Security Verification

## Description
This project is designed to enhance software supply chain security by implementing artifact signing, 
verification using a transparency log (e.g., Rekor), and cryptographic proof verification using Python. 
It includes tools for verifying artifact integrity, verifying Merkle tree inclusion proofs, 
and maintaining consistency between transparency log checkpoints.

## Features
- Signing and verifying artifacts using `cosign`.
- Verifying inclusion of artifacts in a transparency log using `Rekor`.
- Cryptographic proof verification using Merkle proofs.
- Command-line utilities to interact with transparency logs.

## Getting Started

### Installation

1. Clone the repository from GitHub:
   ```sh
   git clone https://github.com/XichengTong/SoftwareSupplyChainSecurity_HW1.git
   cd SoftwareSupplyChainSecurity_HW1
   ```

2. Create a virtual environment and install the required dependencies:
   ```sh
   python -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`
   
  ### Prerequisites
To run the project, you'll need the following software installed:

1. **Python 3.8 or Higher**:
   - Download and install Python from [python.org](https://www.python.org/downloads/).
   - Verify installation:
     ```sh
     python --version
     ```

2. **`rekor-cli`** (for interacting with the Rekor transparency log):
   - Installation using `brew` (macOS) or build from source:
     ```sh
     brew install rekor-cli
     ```
   - For more details, refer to [Rekor CLI GitHub repository](https://github.com/sigstore/rekor).

3. **`cosign`** (for signing and verifying artifacts):
   - Installation using `brew` (macOS):
     ```sh
     brew install cosign
     ```
   - For other platforms, follow instructions on the [Cosign GitHub repository](https://github.com/sigstore/cosign).

4. **`pipenv` or `pip` for Python package management**:
   - Install `pipenv`:
     ```sh
     pip install pipenv
     ```
   - Alternatively, you can use `pip` (comes by default with Python).


### Usage
1. **Signing Artifacts**:
   To sign an artifact, use the `cosign` tool:
   ```sh
   cosign sign --key cosign.key artifact.bundle
   ```

2. **Verifying Artifact Inclusion**:
   To verify inclusion of an artifact in the Rekor transparency log:
   ```sh
   rekor-cli verify --rekor_server <rekor_url> --signature <artifact-signature> --public-key <your_public_key> --artifact <url_to_artifact>|<local_path_artifact>
   ```

3. **Python Scripts**:
   - `main.py`: Entry point to run the application, which includes functions for verifying proofs and signatures.
   - `merkle_proof.py`: Contains methods for computing Merkle leaf hashes and verifying inclusion.
   - `util.py`: Utility functions for processing artifact data.

### Configuration
- Ensure to update `config.json` with relevant configuration values (e.g., API endpoints).
- Add your Rekor server URL and public key in the configuration file.

### Running Tests
Tests are provided to ensure the functionality of key modules:
```sh
pytest tests/
```

## Contributing
Please refer to `CONTRIBUTING.md` for detailed guidelines on how to contribute to the project.

## Security Policy
See `SECURITY.md` for information about how to report security vulnerabilities.

## License
This project is licensed under the MIT License - see the `LICENSE` file for details.