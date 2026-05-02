import os

from tornado.escape import json_decode

from cryptographic_operations.passphrase_operations import (
    SCRYPT_DERIVATION_PARAMS,
    passphrase_hashing,
)
from cryptographic_operations.personal_details_operations import (
    encrypt_plaintext,
    keyed_hashing,
)

from .base import BaseHandler


class RegistrationHandler(BaseHandler):
    async def post(self):
        try:
            body = json_decode(self.request.body)
            email = body["email"].lower().strip()

            hmac_email: str = keyed_hashing(email)
            encrypted_email: str = encrypt_plaintext(email).hex()

            salt = os.urandom(32)
            password = passphrase_hashing(
                passphrase=body["password"],
                salt=salt,
                derivation_params=SCRYPT_DERIVATION_PARAMS,
            )

            display_name = body.get("displayName")
            encrypted_display_name: str = encrypt_plaintext(display_name).hex()
            if display_name is None:
                display_name = email
            if not isinstance(display_name, str):
                raise Exception("Display name must be a string")
        except Exception:
            self.send_error(
                400,
                message="You must provide an email address, password and display name!",
            )
            return

        if not email:
            self.send_error(400, message="The email address is invalid!")
            return

        if not password:
            self.send_error(400, message="The password is invalid!")
            return

        if not display_name:
            self.send_error(400, message="The display name is invalid!")
            return

        user = await self.db.users.find_one({"key_hashed_email": hmac_email})

        if user is not None:
            self.send_error(
                409, message="A user with the given email address already exists!"
            )
            return

        await self.db.users.insert_one(
            {
                "key_hashed_email": hmac_email,
                "email": encrypted_email,
                "displayName": encrypted_display_name,
                "password": password,
                "salt": salt.hex(),
            }
        )

        self.set_status(200)
        self.response["email"] = email
        self.response["displayName"] = display_name

        self.write_json()
