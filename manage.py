import os
import unittest

from app import create_app


app = create_app()


# Support running integration tests
@app.cli.command()
def test():
    """Run integration tests."""
    tests = unittest.TestLoader().discover(os.path.join(os.path.dirname(__file__), 'tests'))
    unittest.TextTestRunner(verbosity=2).run(tests)


# Support PyCharm debugging
if 'PYCHARM_HOSTED' in os.environ:
    # Exempting Bandit security issue (binding to all network interfaces)
    #
    # All interfaces option used because the network available within the container can vary across providers
    # This is only used when debugging with PyCharm. A standalone web server is used in production.
    app.run(host='0.0.0.0', port=9000, debug=True, use_debugger=False, use_reloader=False)  # nosec
