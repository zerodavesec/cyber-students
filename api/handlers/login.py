from datetime import datetime, timedelta, timezone
from uuid import uuid4

from tornado.escape import json_decode

from cryptographic_operations.passphrase_operations import (
    SCRYPT_DERIVATION_PARAMS,
    passphrase_verification,
)

from .base import BaseHandler


class LoginHandler(BaseHandler):
    async def generate_token(self, email):
        token_uuid = uuid4().hex
        expires_in = (datetime.now(timezone.utc) + timedelta(hours=2)).timestamp()

        token = {
            "token": token_uuid,
            "expiresIn": expires_in,
        }

        await self.db.users.update_one({"email": email}, {"$set": token})

        return token

    async def post(self):
        try:
            body = json_decode(self.request.body)
            email = body["email"].lower().strip()
            password = body["password"]
        except Exception:
            self.send_error(
                400, message="You must provide an email address and password!"
            )
            return

        if not email:
            self.send_error(400, message="The email address is invalid!")
            return

        if not password:
            self.send_error(400, message="The password is invalid!")
            return

        ## Addition to find salt as well in database.
        user = await self.db.users.find_one(
            {"email": email}, {"password": 1, "salt": 1}
        )

        if user is None:
            self.send_error(403, message="The email address and password are invalid!")
            return

        pass_verification_result = passphrase_verification(
            password=password,
            hashed_passphrase=user["password"],
            salt=bytes.fromhex(user["salt"]),
            derivation_params=SCRYPT_DERIVATION_PARAMS,
        )

        if pass_verification_result is False:
            self.send_error(403, message="The email address and password are invalid!")
            return

        token = await self.generate_token(email)

        self.set_status(200)
        self.response["token"] = token["token"]
        self.response["expiresIn"] = token["expiresIn"]

        self.write_json()
