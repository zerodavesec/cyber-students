import os
from logging import StreamHandler
from unittest import TestCase
from uuid import uuid4

from cryptographic_operations.passphrase_operations import (
    SCRYPT_DERIVATION_PARAMS,
    passphrase_hashing,
    passphrase_verification,
)
from cryptographic_operations.token_operations import sha256_string_hashing


class CrytographicOperationsTesting(TestCase):
    ## TOKEN TESTS
    def test_same_token_same_hash(self):
        token: str = uuid4().hex
        self.assertEqual(sha256_string_hashing(token), sha256_string_hashing(token))

    def test_different_token_different_hash(self):
        token: str = uuid4().hex
        for i in range(100000):
            token2 = uuid4().hex
            self.assertNotEqual(
                sha256_string_hashing(token), sha256_string_hashing(token2)
            )

    ## PASSPHRASE TESTS
    def test_passphrase_successful_verification(self):
        passphrase: str = "SecretPassphrase"
        salt: bytes = os.urandom(32)

        hashed_passphrase: str = passphrase_hashing(
            passphrase=passphrase, salt=salt, derivation_params=SCRYPT_DERIVATION_PARAMS
        )
        self.assertTrue(
            passphrase_verification(
                password=passphrase,
                hashed_passphrase=hashed_passphrase,
                salt=salt,
                derivation_params=SCRYPT_DERIVATION_PARAMS,
            )
        )

    def test_different_salt_different_hashes(self):
        passphrase: str = "SecretPassphrase"
        salt_1: bytes = os.urandom(32)
        salt_2: bytes = os.urandom(32)

        hashed_passphrase_1: str = passphrase_hashing(
            passphrase=passphrase,
            salt=salt_1,
            derivation_params=SCRYPT_DERIVATION_PARAMS,
        )

        hashed_passphrase_2: str = passphrase_hashing(
            passphrase=passphrase,
            salt=salt_2,
            derivation_params=SCRYPT_DERIVATION_PARAMS,
        )

        self.assertNotEqual(salt_1, salt_2)
        self.assertNotEqual(hashed_passphrase_1, hashed_passphrase_2)

    def test_different_passphrase_different_salts_different_hash(self):
        passphrase_1: str = "SecretPassphrase"
        passphrase_2: str = "TopSecretPassphrase"
        salt_1: bytes = os.urandom(32)
        salt_2: bytes = os.urandom(32)

        hashed_passphrase_1: str = passphrase_hashing(
            passphrase=passphrase_1,
            salt=salt_1,
            derivation_params=SCRYPT_DERIVATION_PARAMS,
        )

        hashed_passphrase_2: str = passphrase_hashing(
            passphrase=passphrase_2,
            salt=salt_2,
            derivation_params=SCRYPT_DERIVATION_PARAMS,
        )

        self.assertNotEqual(salt_1, salt_2)
        self.assertNotEqual(hashed_passphrase_1, hashed_passphrase_2)
