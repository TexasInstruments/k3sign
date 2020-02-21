import os
import logging
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend


def hkdf_derive_key(key, salt, num_iterations):
    backend = default_backend()
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=None,
        backend=backend
    )
    tmp_key = key
    for i in range(num_iterations):
        tmp_key = hkdf.derive(tmp_key)
    out_key = tmp_key
    logging.error("HKDF not yet tested")
    return out_key


def encrypt_binary(input_path,
                   output_path,
                   key_path,
                   derive_key=False,
                   num_iterations=0,
                   **kwargs):

    backend = default_backend()

    try:
        with open(input_path, mode='rb') as fh_in:
            input_bytes = fh_in.read()
    except:
        raise Exception("Unable to open file for reading: " + input_path)

    # Read the key
    try:
        with open(key_path, mode='rb') as fh_in:
            key_bytes = fh_in.read()
    except:
        raise Exception("Unable to open file for reading: " + key_path)

    # Handle Initial Vector(IV)
    iv = kwargs.get('initial_vector', None)
    if iv is None:
        logging.info("Generating IV")
        iv = os.urandom(16)

    if not isinstance(iv, bytes):
        raise TypeError(
            "initial_vector is not of type bytes. It is of type  " + str(type(iv)))

    if len(iv) != 16:
        raise ValueError(
            "Expected length of initial_vector is 16 bytes. Actual length is " + str(len(iv)) + " bytes")

    # If key derivation is needed, derive the key
    if derive_key is True:

        # Salt is only needed for key derivation
        salt = kwargs.get('salt', None)
        if salt is None:
            salt = os.urandom(32)

        if not isinstance(salt, bytes):
            raise TypeError(
                "salt is not of type bytes. It is of type  " + str(type(salt)))

        if len(salt) != 32:
            raise ValueError(
                "Expected length of salt is 32 bytes. Actual length is " + str(len(salt)) + " bytes")

        final_key = hkdf_derive_key(key_bytes, salt, num_iterations)
    else:
        final_key = key_bytes

    # Encrypt the file
    cipher = Cipher(algorithms.AES(final_key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    ct = encryptor.update(input_bytes) + encryptor.finalize()

    try:
        with open(output_path, mode='rb') as fh_out:
            fh_out.write(ct)
    except:
        raise Exception("Unable to write to output file")
    return


logging.getLogger().setLevel("DEBUG")
f = "/tmp/1.txt"
encrypt_binary(f, f, f)
