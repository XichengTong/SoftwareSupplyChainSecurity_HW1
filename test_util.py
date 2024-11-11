# tests/test_util.py
import pytest
import base64
import util  # Import your util file
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# Test for extract_public_key()
def test_extract_public_key():
    # Sample base64-encoded PEM certificate
    pem_cert = (
        "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUN6RENDQWxPZ0F3SUJBZ0lVUFp1QVlRWHdhYkl0aXlNMjhmdXVyV0dLcXowd0NnWUlLb1pJemowRUF3TXcKTnpFVk1CTUdBMVVFQ2hNTWMybG5jM1J2Y21VdVpHVjJNUjR3SEFZRFZRUURFeFZ6YVdkemRHOXlaUzFwYm5SbApjbTFsWkdsaGRHVXdIaGNOTWpRd09URXpNVGsxTnpNeVdoY05NalF3T1RFek1qQXdOek15V2pBQU1Ga3dFd1lICktvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRFFnQUVWYWhmdVZWajR4dnB0b2ZBQzEvaDN2Q05pZGtrdGYvVTdHa0UKdVhweUh2S3IzOTFobUxHbmRkYVV1MGxHNmJXTVRDZ0cyS0xGSm5aUzJLcmlWTGpiWktPQ0FYSXdnZ0Z1TUE0RwpBMVVkRHdFQi93UUVBd0lIZ0RBVEJnTlZIU1VFRERBS0JnZ3JCZ0VGQlFjREF6QWRCZ05WSFE0RUZnUVVjbG9ECnV5ZUNuVTBwMk5SNkt2cmszd2VkRmNVd0h3WURWUjBqQkJnd0ZvQVUzOVBwejFZa0VaYjVxTmpwS0ZXaXhpNFkKWkQ4d0hBWURWUjBSQVFIL0JCSXdFSUVPZUhReU1qSTJRRzU1ZFM1bFpIVXdMQVlLS3dZQkJBR0R2ekFCQVFRZQphSFIwY0hNNkx5OW5hWFJvZFdJdVkyOXRMMnh2WjJsdUwyOWhkWFJvTUM0R0Npc0dBUVFCZzc4d0FRZ0VJQXdlCmFIUjBjSE02THk5bmFYUm9kV0l1WTI5dEwyeHZaMmx1TDI5aGRYUm9NSUdLQmdvckJnRUVBZFo1QWdRQ0JId0UKZWdCNEFIWUEzVDB3YXNiSEVUSmpHUjRjbVdjM0FxSktYcmplUEszL2g0cHlnQzhwN280QUFBR1I3UFpYcEFBQQpCQU1BUnpCRkFpQlJaRjFVUGRCT2FEa0NJWnFaQVcvNTBSaDUrYktQOWVTODZ0K3dIblhRSFFJaEFNbmxoMm1TCkFXVkcweFpPWDdhS29KZndLSExhak51NnBxWGlHbTJTcDZncE1Bb0dDQ3FHU000OUJBTURBMmNBTUdRQ01CVGQKWmUzQ0t4dkFheE1oSmJZSjFFRUhjalRpc2ZpZUZHeTkveFJWTElRYmxQVkpJbFBKS3lwNUR0K1hYWlEyNHdJdwpROWRwWHpvS2dueTMrc0hTclRoSEI3aWlwU2J3TjkxYytRQWlRcWVNTjZPR2ludTZyTHFvTlVxTFRSdGdlMjU2Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K"
    )
    pem_bytes = base64.b64decode(pem_cert)

    # Extract the public key
    public_key = util.extract_public_key(pem_bytes)

    # Assert that the key is not None
    assert public_key is not None