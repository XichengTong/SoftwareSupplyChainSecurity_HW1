"""
This module provides functionality for extracting public keys from X.509 certificates 
and verifying the signature of artifacts using elliptic curve digital signatures (ECDSA).

It uses the `cryptography` library to handle certificates, public keys, and signatures.

Functions:
    - extract_public_key(cert): Extracts and returns the public key 
    from a given X.509 certificate (in PEM format).
    - verify_artifact_signature(signature, public_key, artifact_filename): 
    Verifies the digital signature of an artifact file using the given public key.
"""
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.exceptions import InvalidSignature


# extracts and returns public key from a given cert (in pem format)
def extract_public_key(cert):
    """
    Extracts and returns the public key from a given X.509 certificate in PEM format.

    The function takes a PEM-encoded certificate, loads it, extracts the public key, 
    and returns the public key in PEM format.

    Parameters:
        cert (bytes): The X.509 certificate in PEM format.

    Returns:
        bytes: The extracted public key in PEM format.

    Raises:
        ValueError: If the certificate cannot be loaded or the public key cannot be extracted.
    """
    # read the certificate
    #    with open("cert.pem", "rb") as cert_file:
    #        cert_data = cert_file.read()

    # load the certificate
    certificate = x509.load_pem_x509_certificate(cert, default_backend())

    # extract the public key
    public_key = certificate.public_key()

    # save the public key to a PEM file
    #    with open("cert_public.pem", "wb") as pub_key_file:
    #        pub_key_file.write(public_key.public_bytes(
    #            encoding=serialization.Encoding.PEM,
    #            format=serialization.PublicFormat.SubjectPublicKeyInfo
    #        ))
    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return pem_public_key


def verify_artifact_signature(signature, public_key, artifact_filename):
    """
    Verifies the digital signature of an artifact file using the provided public key.

    The function takes the signature, the public key (in PEM format), and the artifact file.
    It reads the artifact file and verifies the signature 
    using ECDSA (Elliptic Curve Digital Signature Algorithm)
    with SHA-256 as the hashing algorithm.

    Parameters:
        signature (bytes): The digital signature to be verified.
        public_key (bytes): The public key in PEM format used to verify the signature.
        artifact_filename (str): The path to the artifact file whose signature needs to be verified.

    Raises:
        InvalidSignature: If the signature is invalid.
        Exception: If there are other issues with the signature verification process.
    """
    # load the public key
    # with open("cert_public.pem", "rb") as pub_key_file:
    #    public_key = load_pem_public_key(pub_key_file.read())

    # load the signature
    #    with open("hello.sig", "rb") as sig_file:
    #        signature = sig_file.read()

    public_key = load_pem_public_key(public_key)
    # load the data to be verified
    with open(artifact_filename, "rb") as data_file:
        data = data_file.read()

    # verify the signature
    try:
        public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        print("Signature is invalid")
    except FileNotFoundError:
        print(f"Artifact file '{artifact_filename}' not found")

    except ValueError:
        print("Invalid public key or signature format")

    except OSError as e:
        print(f"OS error occurred: {e}")
