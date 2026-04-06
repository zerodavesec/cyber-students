import logging
import unittest

## Adding a comment here so I can have a change in files and then commit to a branch
## -> It should create a PR and tests should pass.
from test.login import LoginHandlerTest
from test.logout import LogoutHandlerTest
from test.registration import RegistrationHandlerTest
from test.user import UserHandlerTest
from test.welcome import WelcomeHandlerTest

if __name__ == "__main__":
    logging.getLogger("tornado.access").disabled = True
    unittest.main()
