import os
from json import dumps

from tornado.escape import json_decode
from tornado.ioloop import IOLoop
from tornado.web import Application

from api.handlers.login import LoginHandler
from cryptographic_operations.passphrase_operations import (
    SCRYPT_DERIVATION_PARAMS,
    passphrase_hashing,
)
from cryptographic_operations.personal_details_operations import (
    encrypt_plaintext,
    keyed_hashing,
)

from .base import BaseTest


class LoginHandlerTest(BaseTest):
    @classmethod
    def setUpClass(self):
        self.my_app = Application([(r"/login", LoginHandler)])
        super().setUpClass()

    # For tests to pass on login operations, the .register() method had to be updated
    # for the db to receive a hashed passphrase and a salt in hex.
    async def register(self):
        self.salt = os.urandom(32)
        self.hashed_pwd = passphrase_hashing(
            self.password, self.salt, SCRYPT_DERIVATION_PARAMS
        )
        await self.get_app().db.users.insert_one(
            {
                "key_hashed_email": keyed_hashing(self.email),
                "email": encrypt_plaintext(self.email),
                "password": self.hashed_pwd,
                "salt": self.salt.hex(),
                "displayName": "testDisplayName",
            }
        )

    def setUp(self):
        super().setUp()

        self.email = "test@test.com"
        self.password = "testPassword"

        IOLoop.current().run_sync(self.register)

    def test_login(self):
        body = {"email": self.email, "password": self.password}

        response = self.fetch("/login", method="POST", body=dumps(body))
        self.assertEqual(200, response.code)

        body_2 = json_decode(response.body)
        self.assertIsNotNone(body_2["token"])
        self.assertIsNotNone(body_2["expiresIn"])

    def test_login_case_insensitive(self):
        body = {"email": self.email.swapcase(), "password": self.password}

        response = self.fetch("/login", method="POST", body=dumps(body))
        self.assertEqual(200, response.code)

        body_2 = json_decode(response.body)
        self.assertIsNotNone(body_2["token"])
        self.assertIsNotNone(body_2["expiresIn"])

    def test_login_wrong_email(self):
        body = {"email": "wrongUsername", "password": self.password}

        response = self.fetch("/login", method="POST", body=dumps(body))
        self.assertEqual(403, response.code)

    def test_login_wrong_password(self):
        body = {"email": self.email, "password": "wrongPassword"}

        response = self.fetch("/login", method="POST", body=dumps(body))
        self.assertEqual(403, response.code)
