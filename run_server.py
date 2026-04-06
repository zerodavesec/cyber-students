import os
from logging import INFO, basicConfig, info

import keyring
from tornado.httpserver import HTTPServer
from tornado.ioloop import IOLoop

from api.app import Application
from api.conf import PORT


def initialise_pepper() -> None:
    if keyring.get_password("cyberstudents", "pepper") is None:
        pepper: str = os.urandom(32).hex()
        keyring.set_password("cyberstudents", "pepper", pepper)


def main():
    basicConfig(level=INFO)

    initialise_pepper()

    http_server = HTTPServer(Application())
    http_server.listen(PORT)

    info("Starting server on port " + str(PORT) + "...")
    IOLoop.current().start()


if __name__ == "__main__":
    main()
