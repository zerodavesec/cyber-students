import os
from logging import StreamHandler
from unittest import TestCase
from uuid import uuid4

from cryptographic_operations.passphrase_operations import (
    SCRYPT_DERIVATION_PARAMS,
    passphrase_hashing,
    passphrase_verification,
)
from cryptographic_operations.personal_details_operations import (
    decrypt_cyphertext,
    encrypt_plaintext,
    keyed_hashing,
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

    ## AES-CTR Tests
    def test_encryption_then_decryption_to_same_plaintext(self):
        email: str = "david@zerodave.com"

        nonce_and_ciphertext: bytes = encrypt_plaintext(email)
        plaintext: str = decrypt_cyphertext(nonce_and_ciphertext=nonce_and_ciphertext)

        self.assertEqual(email, plaintext)

    def test_encryption_creates_different_ciphertext_each_time(self):
        email: str = "david@zerodave.com"

        nonce_and_ciphertext: bytes = encrypt_plaintext(email)
        encrypted_nonce: bytes = nonce_and_ciphertext[:16]
        ciphertext: bytes = nonce_and_ciphertext[16:]

        for i in range(1000):
            second_encryption: bytes = encrypt_plaintext(email)
            second_encrypted_nonce: bytes = second_encryption[:16]
            second_ciphertext: bytes = second_encryption[16:]

            self.assertNotEqual(second_encrypted_nonce, encrypted_nonce)
            self.assertNotEqual(second_ciphertext, ciphertext)
            self.assertNotEqual(nonce_and_ciphertext, second_encryption)

    def test_ciphertext_and_plaintext_lenght_is_equal(self):
        email: str = "david@zerodave.com"

        nonce_and_ciphertext: bytes = encrypt_plaintext(email)
        ciphertext: bytes = nonce_and_ciphertext[16:]

        self.assertEqual(len(ciphertext), len(email.encode()))

    # KEYED HASHING Tests
    def test_keyed_hashing_produces_same_output_with_same_input(self):
        email: str = "david@zerodave.com"

        hash_1: str = keyed_hashing(email)
        hash_2: str = keyed_hashing(email)

        self.assertEqual(hash_1, hash_2)

    def test_keyed_hashing_different_input_different_output(self):
        email_1: str = "david@zerodave.com"
        email_2: str = "martin@test.com"

        hash_1: str = keyed_hashing(email_1)
        hash_2: str = keyed_hashing(email_2)

        self.assertNotEqual(hash_1, hash_2)

    def test_keyed_hashing_returns_sha_256_length(self):
        email: str = "david@zerodave.com"
        hash: str = keyed_hashing(email)

        self.assertEqual(len(hash), 64)

    def test_keyed_hashing_returns_hexadecimal_string(self):
        email: str = "david@zerodave.com"
        hash: str = keyed_hashing(email)

        self.assertTrue(all(character in "0123456789abcdef" for character in hash))
