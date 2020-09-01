import os
import sys
import unittest

import xmlrunner


with open("test-results.xml", "wb") as output:
    tests = unittest.TestLoader().discover(os.path.join(os.path.dirname(__file__), "tests"))
    tests_runner = xmlrunner.XMLTestRunner(output=output)
    sys.exit(not tests_runner.run(tests).wasSuccessful())
