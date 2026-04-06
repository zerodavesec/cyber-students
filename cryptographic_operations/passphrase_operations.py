import os
from typing import cast

import keyring
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# For password hashing, using Scrypt with the following values:
#               N = 2**14, r = 8, p = 1, length = 32
#
# To compute one hashed password the required memory will be:
#  required_memory = 128 * N * r -> 16 MB per calculation.
# Because this is the backend for a webapp, to prevent login storms causing
# memory strain, 16 MB is ok.

SCRYPT_DERIVATION_PARAMS: dict[str, int] = {"length": 32, "N": 2**14, "r": 8, "p": 1}
PEPPER: str = keyring.get_password("cyberstudents", "pepper")  # type: ignore


def passphrase_hashing(
    passphrase: str, salt: bytes, derivation_params: dict[str, int]
) -> str:
    key_derivation_function: Scrypt = Scrypt(
        salt=salt,
        length=derivation_params["length"],
        n=derivation_params["N"],
        r=derivation_params["r"],
        p=derivation_params["p"],
    )
    derived_passphrase: bytes = key_derivation_function.derive(
        passphrase.encode() + PEPPER.encode()
    )
    return derived_passphrase.hex()


def password_verification(): ...
