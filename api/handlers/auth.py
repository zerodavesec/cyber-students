from datetime import datetime, timezone

from cryptographic_operations.personal_details_operations import decrypt_cyphertext
from cryptographic_operations.token_operations import sha256_string_hashing

from .base import BaseHandler


class AuthHandler(BaseHandler):
    async def prepare(self):
        super(AuthHandler, self).prepare()

        if self.request.method == "OPTIONS":
            return

        try:
            token = self.request.headers.get("X-Token")
            if not token:
                raise Exception()
        except Exception:
            self.current_user = None
            self.send_error(400, message="You must provide a token!")
            return

        hashed_token: str = sha256_string_hashing(token)
        user = await self.db.users.find_one(
            {"token": hashed_token},
            {"encrypted_email": 1, "displayName": 1, "expiresIn": 1},
        )

        if user is None:
            self.current_user = None
            self.send_error(403, message="Your token is invalid!")
            return

        current_time = datetime.now(timezone.utc).timestamp()
        if current_time > user["expiresIn"]:
            self.current_user = None
            self.send_error(403, message="Your token has expired!")
            return

        # user contains data directly from database (encrypted), must be decrypted
        # before printing. This data goes to user.py to be printed.
        # Decision is to decrypt it here instead of in user.py.
        self.current_user = {
            "email": decrypt_cyphertext(bytes.fromhex(user["encrypted_email"])),
            "display_name": decrypt_cyphertext(bytes.fromhex(user["displayName"])),
        }
