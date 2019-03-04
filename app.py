import os
import unittest

from http import HTTPStatus

from flask import Flask, request, jsonify

from tests.utils import TestJwk, TestFlaskAzureOauth

config = {
    'AZURE_OAUTH_TENANCY': 'test',
    'AZURE_OAUTH_APPLICATION_ID': 'test',
    'AZURE_OAUTH_CLIENT_APPLICATION_IDS': ['test', 'test2'],
    'TEST_JWKS': TestJwk()
}


def create_app(**kwargs):
    app = Flask(__name__)
    app.config['AZURE_OAUTH_TENANCY'] = config['AZURE_OAUTH_TENANCY']
    app.config['AZURE_OAUTH_APPLICATION_ID'] = config['AZURE_OAUTH_APPLICATION_ID']
    app.config['AZURE_OAUTH_CLIENT_APPLICATION_IDS'] = config['AZURE_OAUTH_CLIENT_APPLICATION_IDS']
    app.config['TEST_JWKS'] = config['TEST_JWKS']

    app.auth = TestFlaskAzureOauth(
        azure_tenancy_id=app.config['AZURE_OAUTH_TENANCY'],
        azure_application_id=app.config['AZURE_OAUTH_APPLICATION_ID'],
        azure_client_application_ids=app.config['AZURE_OAUTH_CLIENT_APPLICATION_IDS'],
        azure_jwks=app.config['TEST_JWKS'].jwks()
    )

    # Support invalid ways of setting up the auth provider when testing
    if 'AUTH_MODE' in kwargs:
        if kwargs['AUTH_MODE'] == 'null-jwks':
            app.auth.use_null_jwks()
        elif kwargs['AUTH_MODE'] == 'broken-jwks':
            app.auth.use_broken_jwks()
        elif kwargs['AUTH_MODE'] == 'replaced-jwks':
            app.auth.use_replaced_jwks()
        elif kwargs['AUTH_MODE'] == 'restored-jwks':
            app.auth.use_restored_jwks()

    # Support running integration tests
    @app.cli.command()
    def test():
        """Run integration tests."""
        tests = unittest.TestLoader().discover(os.path.join(os.path.dirname(__file__), 'tests'))
        unittest.TextTestRunner(verbosity=2).run(tests)

    @app.route('/meta/auth/introspection')
    @app.auth()
    def meta_auth_introspection():
        authorization_header = request.headers.get('authorization')
        token_string = authorization_header.split('Bearer ')[1]

        payload = {
            'data': {
                'token': app.auth.introspect_token(token_string=token_string),
                'token-string': token_string
            }
        }

        return jsonify(payload)

    @app.route('/meta/auth/insufficient-scopes')
    @app.auth('unobtainable-scope')
    def meta_auth_insufficient_scopes():
        """
        Simulates a resource a client doesn't have access to due to not having the correct scopes.

        In practice it is impossible to access this resource.
        """
        return '', HTTPStatus.NO_CONTENT

    return app


if __name__ == "__main__":
    test_app = create_app()

    # Support PyCharm debugging
    if 'PYCHARM_HOSTED' in os.environ:
        # Exempting Bandit security issue (binding to all network interfaces)
        #
        # All interfaces option used because the network available within the container can vary across providers
        # This is only used when debugging with PyCharm. A standalone web server is used in production.
        test_app.run(host='0.0.0.0', port=9000, debug=True, use_debugger=False, use_reloader=False)  # nosec
