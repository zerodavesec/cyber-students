from logging import StreamHandler
from unittest import TestCase
from uuid import uuid4

from cryptographic_operations.passphrase_operations import *
from cryptographic_operations.token_operations import sha256_string_hashing


class CrytographicOperationsTesting(TestCase):
    def test_same_token_same_hash(self):
        token = uuid4().hex
        self.assertEqual(sha256_string_hashing(token), sha256_string_hashing(token))

    def test_different_token_different_hash(self):
        token = uuid4().hex
        for i in range(100000):
            token2 = uuid4().hex
            self.assertNotEqual(
                sha256_string_hashing(token), sha256_string_hashing(token2)
            )
