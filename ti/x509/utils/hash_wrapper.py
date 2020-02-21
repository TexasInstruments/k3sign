from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from ti.x509.extensions import ImageComponentExtension


def hash_binary(inp_bytes, **kwargs):
    digest = hashes.Hash(hashes.SHA512(), backend=default_backend())
    digest.update(inp_bytes)
    hash_val = digest.finalize()
    return hash_val.hex()


def hash_binary_into_ImageCompExtension(inp_bytes):
    bin_hash = hash_binary(inp_bytes)
    ext = ImageComponentExtension()
    ext.compSize = len(inp_bytes)
    ext.shaValue = bin_hash
    return ext
