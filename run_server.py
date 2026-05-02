import os
from logging import INFO, basicConfig, info

import keyring
from tornado.httpserver import HTTPServer
from tornado.ioloop import IOLoop

from api.app import Application
from api.conf import PORT
from cryptographic_operations.passphrase_operations import initialise_pepper
from cryptographic_operations.personal_details_operations import (
    initialise_aes_key,
    initialise_hmac_key,
)


def main():
    basicConfig(level=INFO)

    initialise_pepper()
    initialise_aes_key()
    initialise_hmac_key()

    http_server = HTTPServer(Application())
    http_server.listen(PORT)

    info("Starting server on port " + str(PORT) + "...")
    IOLoop.current().start()


if __name__ == "__main__":
    main()
