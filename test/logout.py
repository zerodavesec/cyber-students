import os
from json import dumps

from tornado.escape import json_decode
from tornado.httputil import HTTPHeaders
from tornado.ioloop import IOLoop
from tornado.web import Application

from api.handlers.logout import LogoutHandler
from cryptographic_operations.passphrase_operations import (
    SCRYPT_DERIVATION_PARAMS,
    passphrase_hashing,
)
from cryptographic_operations.personal_details_operations import (
    encrypt_plaintext,
    keyed_hashing,
)
from cryptographic_operations.token_operations import sha256_string_hashing

from .base import BaseTest


class LogoutHandlerTest(BaseTest):
    @classmethod
    def setUpClass(self):
        self.my_app = Application([(r"/logout", LogoutHandler)])
        super().setUpClass()

    async def register(self):
        self.salt = os.urandom(32)
        self.hashed_pwd = passphrase_hashing(
            self.password, self.salt, SCRYPT_DERIVATION_PARAMS
        )
        await self.get_app().db.users.insert_one(
            {
                "email": encrypt_plaintext(self.email).hex(),
                "key_hashed_email": keyed_hashing(self.email),
                "displayName": encrypt_plaintext("testDisplayName").hex(),
                "password": self.hashed_pwd,
                "salt": self.salt.hex(),
            }
        )

    async def login(self):
        await self.get_app().db.users.update_one(
            {"key_hashed_email": keyed_hashing(self.email)},
            {
                "$set": {
                    "token": sha256_string_hashing(self.token),
                    "expiresIn": 2147483647,
                }
            },
        )

    def setUp(self):
        super().setUp()

        self.email = "test@test.com"
        self.password = "testPassword"
        self.token = "testToken"

        IOLoop.current().run_sync(self.register)
        IOLoop.current().run_sync(self.login)

    def test_logout(self):
        headers = HTTPHeaders({"X-Token": self.token})
        body = {}

        response = self.fetch(
            "/logout", headers=headers, method="POST", body=dumps(body)
        )
        self.assertEqual(200, response.code)

    def test_logout_without_token(self):
        body = {}

        response = self.fetch("/logout", method="POST", body=dumps(body))
        self.assertEqual(400, response.code)

    def test_logout_wrong_token(self):
        headers = HTTPHeaders({"X-Token": "wrongToken"})
        body = {}

        response = self.fetch("/logout", method="POST", body=dumps(body))
        self.assertEqual(400, response.code)

    def test_logout_twice(self):
        headers = HTTPHeaders({"X-Token": self.token})
        body = {}

        response = self.fetch(
            "/logout", headers=headers, method="POST", body=dumps(body)
        )
        self.assertEqual(200, response.code)

        response_2 = self.fetch(
            "/logout", headers=headers, method="POST", body=dumps(body)
        )
        self.assertEqual(403, response_2.code)
