import os
from json import dumps

from tornado.escape import json_decode
from tornado.httputil import HTTPHeaders
from tornado.ioloop import IOLoop
from tornado.web import Application

from api.handlers.user import UserHandler
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


class UserHandlerTest(BaseTest):
    @classmethod
    def setUpClass(self):
        self.my_app = Application([(r"/user", UserHandler)])
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
        self.display_name = "testDisplayName"
        self.token = "testToken"

        IOLoop.current().run_sync(self.register)
        IOLoop.current().run_sync(self.login)

    def test_user(self):
        headers = HTTPHeaders({"X-Token": self.token})

        response = self.fetch("/user", headers=headers)
        self.assertEqual(200, response.code)

        body_2 = json_decode(response.body)
        self.assertEqual(self.email, body_2["email"])
        self.assertEqual(self.display_name, body_2["displayName"])

    def test_user_without_token(self):
        response = self.fetch("/user")
        self.assertEqual(400, response.code)

    def test_user_wrong_token(self):
        headers = HTTPHeaders({"X-Token": "wrongToken"})

        response = self.fetch("/user")
        self.assertEqual(400, response.code)
