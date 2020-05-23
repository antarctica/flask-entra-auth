import os
import sys
import unittest

import xmlrunner

from click import option, Choice, echo, style

from app import create_test_app


app = create_test_app()


# Support running integration tests
@app.cli.command()
def test():
    """Run integration tests."""
    tests = unittest.TestLoader().discover(os.path.join(os.path.dirname(__file__), "tests"))
    unittest.TextTestRunner(verbosity=2).run(tests)


@app.cli.command()
@option("--test-runner", type=Choice(["text", "junit"]))
def test(test_runner: str = "text"):
    """Run integration tests."""
    tests = unittest.TestLoader().discover(os.path.join(os.path.dirname(__file__), "tests"))

    if test_runner == "text":
        tests_runner = unittest.TextTestRunner(verbosity=2)
        return sys.exit(not tests_runner.run(tests).wasSuccessful())
    elif test_runner == "junit":
        with open("test-results.xml", "wb") as output:
            tests_runner = xmlrunner.XMLTestRunner(output=output)
            return sys.exit(not tests_runner.run(tests).wasSuccessful())

    echo(style("Unknown Python unit test runner type", fg="red"), err=True)


# Support PyCharm debugging
if "PYCHARM_HOSTED" in os.environ:
    # Exempting Bandit security issue (binding to all network interfaces)
    #
    # All interfaces option used because the network available within the container can vary across providers
    # This is only used when debugging with PyCharm. A standalone web server is used in production.
    app.run(host="0.0.0.0", port=9000, debug=True, use_debugger=False, use_reloader=False)  # nosec
