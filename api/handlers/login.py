from datetime import datetime, timedelta, timezone
from uuid import uuid4

from tornado.escape import json_decode

from cryptographic_operations.passphrase_operations import (
    SCRYPT_DERIVATION_PARAMS,
    passphrase_verification,
)
from cryptographic_operations.token_operations import sha256_string_hashing

from .base import BaseHandler


class LoginHandler(BaseHandler):
    async def generate_token(self, email) -> dict[str, str | float]:
        # OWASP requires at least 64bits of entropy to prevent brute-force session guessing attacks
        # https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
        # UUIDv4 meets this as it is created randomly from the uuid4() declaration:,
        # def uuid4():
        #     """Generate a random UUID."""
        #     int_uuid_4 = int.from_bytes(os.urandom(16))
        #     int_uuid_4 &= _RFC_4122_CLEARFLAGS_MASK
        #     int_uuid_4 |= _RFC_4122_VERSION_4_FLAGS
        #     return UUID._from_int(int_uuid_4)
        #
        # The final result is that uuid4 created with Python has 122 bits of entropy and
        # 6 hardcoded bits (deterministic). An attacker would need to brute force a 2**122 space

        token_uuid: str = uuid4().hex
        hashed_uuid: str = sha256_string_hashing(token_uuid)
        expires_in: float = (
            datetime.now(timezone.utc) + timedelta(hours=2)
        ).timestamp()

        token: dict[str, str | float] = {"token": token_uuid, "expiresIn": expires_in}

        hashed_token: dict[str, str | float] = {
            "token": hashed_uuid,
            "expiresIn": expires_in,
        }

        await self.db.users.update_one({"email": email}, {"$set": hashed_token})

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
