from tornado.web import authenticated

from .auth import AuthHandler


class UserHandler(AuthHandler):
    ## self.current_user['email'] and self.current_user['display_name'] are
    # decrypted in auth.py, those values are plaintext here to be printed.
    @authenticated
    def get(self):
        self.set_status(200)
        self.response["email"] = self.current_user["email"]
        self.response["displayName"] = self.current_user["display_name"]
        self.write_json()
