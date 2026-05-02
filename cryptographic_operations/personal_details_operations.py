import os

import keyring
from cryptography.hazmat.primitives.ciphers import (
    AEADDecryptionContext,
    AEADEncryptionContext,
    Cipher,
)
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import CTR
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.hmac import HMAC


def initialise_aes_key() -> None:
    if keyring.get_password("myapp", "AES_KEY") is None:
        aes_key: str = os.urandom(32).hex()
        keyring.set_password("myapp", "AES_KEY", aes_key)


def initialise_hmac_key() -> None:
    if keyring.get_password("myapp", "HMAC_KEY") is None:
        hmac_key: str = os.urandom(32).hex()
        keyring.set_password("myapp", "HMAC_KEY", hmac_key)


def encrypt_plaintext(plaintext: str) -> bytes:
    aes_key: bytes = bytes.fromhex(keyring.get_password("myapp", "AES_KEY"))  # type: ignore
    nonce: bytes = os.urandom(16)

    aes_ctr: Cipher = Cipher(AES(aes_key), CTR(nonce))
    aes_ctr_encryptor: AEADEncryptionContext = aes_ctr.encryptor()

    ciphertext: bytes = (
        aes_ctr_encryptor.update(plaintext.encode()) + aes_ctr_encryptor.finalize()
    )

    return nonce + ciphertext


def decrypt_cyphertext(nonce_and_ciphertext: bytes) -> str:
    aes_key: bytes = bytes.fromhex(keyring.get_password("myapp", "AES_KEY"))  # type: ignore

    nonce: bytes = nonce_and_ciphertext[:16]
    ciphertext: bytes = nonce_and_ciphertext[16:]

    aes_ctr: Cipher = Cipher(AES(aes_key), CTR(nonce))
    aes_ctr_decryptor: AEADDecryptionContext = aes_ctr.decryptor()

    plaintext: str = (
        aes_ctr_decryptor.update(ciphertext) + aes_ctr_decryptor.finalize()
    ).decode()

    return plaintext


# The need for using keyed hashing comes from the fact that AES-CTR will create a different
# ciphertext each time, even when the input email is the same, because of the randomised nonce.
# A test like the one for tokens where the token is hashed then the value checked against
# the value in the DB cannot ocurr here as ciphertexts will differ.
# https://medium.com/@joshuakelly/blind-indexes-in-3-minutes-making-encrypted-personal-data-searchable-b26bce99ce7c
# The solution below is to use keyed hashing:
#  1. The email verification will ocurr using keyed hashing HMAC-SHA-256
#  2. The email encryption/storage/decryption will ocurr using AES-CTR
def keyed_hashing(email: str) -> str:
    hmac_key: bytes = bytes.fromhex(keyring.get_password("myapp", "HMAC_KEY"))  # type: ignore

    hmac: HMAC = HMAC(hmac_key, SHA256())
    hmac.update(email.encode())

    hash: str = hmac.finalize().hex()

    return hash
