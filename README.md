# Flask Azure AD OAuth Provider

Python Flask extension for securing apps with Azure Active Directory OAuth

## Purpose

Provide an [AuthLib](https://authlib.org)
[Resource Protector/Server](https://docs.authlib.org/en/latest/flask/2/resource-server.html) to authenticate and
authorise users and applications using a Flask application with OAuth functionality offered by
[Azure Active Directory](https://azure.microsoft.com/en-us/services/active-directory/), as part of the
[Microsoft identity platform](https://docs.microsoft.com/en-us/azure/active-directory/develop/about-microsoft-identity-platform).

Azure Active Directory, acting as an identity provider, issues
[OAuth access tokens](https://docs.microsoft.com/en-us/azure/active-directory/develop/access-tokens), the claims of
which are validated by this provider. These claims include the identity of the user and client application (used for
authentication), and any permissions/scopes assigned or delegated to the user or application (used for authorisation).

This provider supports these scenarios:

1. *application to application*
   * supports authentication and authorisation
   * used to allow a client application access to some functionality or resources provided by another application
   * can be used for non-interactive, machine-to-machine, processes (using the OAuth Client Credentials Grant)
   * optionally, uses the identity of the client application for authentication
   * optionally, uses permissions assigned directly to the client application for authorisation
2. *user to application*
   * supports authentication and authorisation
   * used to allow users access to some functionality or resources provided by another application
   * can be used for interactive console (using the Device Authorization Grant) or web application (using the OAuth
     Authorization Code Grant) processes
   * uses the identity of the user, and optionally, the client application they are using, for authentication
   * optionally, uses permissions assigned to the user, permissions delegated by the user to the client application,
     and/or permissions assigned directly to the client application for authorisation

Other scenarios may work but are not officially supported, this may change in the future.

**Note:** This provider does not support client applications requesting tokens from Azure. See the
[Microsoft Authentication Library (MSAL) for Python](https://github.com/AzureAD/microsoft-authentication-library-for-python)
package if you need to do this.

**Note:** This provider has been written to solve an internal need within applications used by the British Antarctic
Survey. It is offered to others in the hope that's useful for your needs as well, however it does not (and cannot)
cover every option available.

## Installation

This package can be installed using Pip from [PyPi](https://pypi.org/project/flask-azure-oauth):

```
$ pip install flask-azure-oauth
```

**Note:** Since version 0.6.0, this package requires Flask 2.0 or greater.

## Usage

This provider provides an [AuthLib](https://authlib.org)
[Resource Protector](https://docs.authlib.org/en/latest/flask/2/resource-server.html) which can be used as a decorator
on Flask routes.

A minimal application would look like this:

```python
from flask import Flask

from flask_azure_oauth import FlaskAzureOauth

app = Flask(__name__)

app.config['AZURE_OAUTH_TENANCY'] = 'xxx'
app.config['AZURE_OAUTH_APPLICATION_ID'] = 'xxx'

auth = FlaskAzureOauth()
auth.init_app(app)

@app.route('/unprotected')
def unprotected():
    return 'hello world'

@app.route('/protected')
@auth()
def protected():
    return 'hello authenticated entity'

@app.route('/protected-with-single-scope')
@auth('required-scope')
def protected_with_scope():
    return 'hello authenticated and authorised entity'

@app.route('/protected-with-multiple-scopes')
@auth('required-scope1 required-scope2')
def protected_with_multiple_scopes():
    return 'hello authenticated and authorised entity'
```

To restrict a route to any valid user or client application (authentication):

* add the resource protector as a decorator (`auth` in this example) - for example the `/protected` route

To restrict a route to specific users (authorisation):

* add any required [Scopes](#permissions-roles-and-scopes) to the decorator - for example the `/projected-with-*` routes

Independently of these options, it's possible to require specific, trusted, client applications, regardless of the user
using them. This is useful in circumstances where a user may be authorised but the client can't be trusted:

* set the `AZURE_OAUTH_CLIENT_APPLICATION_IDS` config option to a list of Azure application identifiers

For example:

```
app.config['AZURE_OAUTH_CLIENT_APPLICATION_IDS'] = ['xxx']`
```

### Configuration options

The resource protector requires two configuration options to validate tokens correctly. These are read from the Flask
[config object](http://flask.pocoo.org/docs/1.0/config/) through the `init_app()` method.

| Configuration Option                 | Data Type | Required | Description                                                                                                                |
| ------------------------------------ | --------- | -------- | -------------------------------------------------------------------------------------------------------------------------- |
| `AZURE_OAUTH_TENANCY`                | Str       | Yes      | ID of the Azure AD tenancy all applications and users are registered within                                                |
| `AZURE_OAUTH_APPLICATION_ID`         | Str       | Yes      | ID of the Azure AD application registration for the application being protected                                            |
| `AZURE_OAUTH_CLIENT_APPLICATION_IDS` | List[Str] | No       | ID(s) of the Azure AD application registration(s) for the application(s) granted access to the application being protected |

**Note:** If the `AZURE_OAUTH_CLIENT_APPLICATION_IDS` option is not set, all client applications will be trusted and the
`azp` claim, if present, is ignored.

Before these options can be set you will need to:

1. [register the application to be protected](#registering-an-application-in-azure)
2. [define the permissions and roles this application supports](#defining-permissions-and-roles-within-an-application)
3. [register the application(s) that will use the protected application](#registering-an-application-in-azure)
4. [assign permissions to users and/or client application(s)](#assigning-permissions-and-roles-to-users-and-applications)

### Flask session support

This provider extends the AuthLib ResourceProtector to support detecting access tokens stored in the Flask session.

This is intended for browser based applications where the `Authorization` header cannot be easily set to include the
access token. This support will be enabled automatically if an `access_token` session key is set.

### Access token versions

Since version 0.5.0, this provider is compatible with Azure access token versions 1.0 and 2.0. Prior to version 0.5.0
only version 2.0 tokens could be used. See
[Microsoft's documentation](https://docs.microsoft.com/en-us/azure/active-directory/develop/access-tokens) for the
differences between token versions.

**Note:** If you use version 1.0 tokens, this provider expects at least one of the `identifierUris` property values to
be `api://{protected_application_id}`, where `{protected_application_id}` is the application ID of the app registration
representing the application being protected by this provider. Without this, you will receive errors for an invalid
audience.

### Applications, users, groups and tenancies

Azure Active Directory has a number of different concepts for agents that represent things being protected and things
that want to interact with protected things:

* [applications](https://docs.microsoft.com/en-us/azure/active-directory/develop/authentication-scenarios#application-model) -
  represent services that offer, or wish to use, functionality that should be restricted:
    * services offering functionality are *protected applications*, e.g. an API
    * services wishing to use functionality interactively or non-interactively, are *client applications*:
        * interactive client applications include self-service portals for example
         * non-interactive client applications include nightly synchronisation tasks for example
* [users](https://docs.microsoft.com/en-us/azure/active-directory/users-groups-roles/directory-overview-user-model) -
  represent individuals that wish to use functionality offered by protected applications, through one or more
  client applications (e.g. a user may use a self-service portal to access information)
* [groups](https://docs.microsoft.com/en-us/azure/active-directory/users-groups-roles/directory-overview-user-model) -
  represent multiple users, for ease of managing permissions to similar users (e.g. administrative users)

For management purposes, all agents are scoped to an Azure tenancy (with the exception of users that can be used across
tenancies).

In the Azure management portal:

* applications are represented by *Application registrations*
* users are represented by *users*, or optionally *groups* of users

### Permissions, roles and scopes

Azure Active Directory has a number of mechanisms for controlling how agents can interact with each other:

* [roles](https://docs.microsoft.com/en-us/azure/architecture/multitenant-identity/app-roles) - functions, designations
  or labels conferred on users and/or groups (e.g. `admins`, `staff`)
* [direct permissions](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-permissions-and-consent) -
  capabilities of a protected application client applications can use themselves or without the consent of the current
  user (e.g. machine-to-machine access to, or modification of, data from all users)
* [delegated permissions](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-permissions-and-consent) -
  capabilities of a protected application the current user allows a client application to use (e.g. interactive access
  to, or modification of, their data)

Generally, and in terms of the OAuth ecosystem, all of these can be considered as
[scopes](https://tools.ietf.org/html/rfc6749#section-3.3). As discussed in the [Usage](#usage) section, scopes can be
used to control who and/or what can use features within protected applications.

Scopes are included the access token generated by a client application (possibly interactively by a user) and presented
to the projected application as a bearer token. Azure encodes different mechanisms in different claims:

* `roles` - for roles assigned to users and permissions directly assigned to client applications
* `scp` - for permissions delegated by the user to a client application

For ease of use, this extension abstracts these two claims into a single set of `scopes` that can be required for a
given route. Multiple scopes can be required (as a logical AND) to allow scopes to be used more flexibly.

#### Defining permissions and roles within an application

Permissions and roles are defined in the
[application manifest](https://docs.microsoft.com/en-us/azure/active-directory/develop/reference-app-manifest) of each
application being protected. They can then be [assigned](#assigning-permissions-and-roles-to-users-and-applications) to
users, groups and client applications.

1. [register](#registering-an-application-in-azure) the application to be protected
2. [add permissions to application manifest](https://docs.microsoft.com/en-us/azure/active-directory/develop/howto-add-app-roles-in-azure-ad-apps)

For example:

```json
"appRoles": [
  {
    "allowedMemberTypes": [
      "Application"
    ],
    "displayName": "List all Foo resources",
    "id": "112b3a76-2dd0-4d09-9976-9f94b2ed965d",
    "isEnabled": true,
    "description": "Allows access to basic information for all Foo resources",
    "value": "Foo.List.All"
  }
],
```

#### Assigning permissions and roles to users and applications

Permissions and roles (collectively, application roles) are assigned through the Azure portal:

1. [define roles and permissions in the protected application](#defining-permissions-and-roles-within-an-application)
2. [register](#registering-an-application-in-azure) the client application(s)
3. assign:
    * [roles to users/groups](https://docs.microsoft.com/en-us/azure/active-directory/develop/howto-add-app-roles-in-azure-ad-apps)
    * [permissions to client applications](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-client-creds-grant-flow#request-the-permissions-in-the-app-registration-portal)

For assigning permissions:

* permissions can be delegated to client applications, with the agreement of the current user
* permissions can be directly assigned to client applications, with the agreement of a tenancy administrator

**Note:** Direct assignment is needed for non-interactive applications, such as daemons.

#### Registering an application in Azure

[Follow these instructions](https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app).

**Note:** These instructions apply both to applications that protected by this provider (protected applications), and
those that will be granted access to use such applications, possibly by a user (client applications).

### Testing support

For testing applications, a local/test JSON Web Key Set (JWKS) can be used to sign local/test JSON Web Tokens (JWTs)
without relying on Azure. Local tokens can include, or not include, arbitrary scopes/roles, which can ensure
requirements for specific scopes are properly enforced by this provider.

This requires using local tokens signed by the test keys, and patching the `FlaskAzureOauth._get_jwks` method to
validate tokens using the same test keys.

For example:

```python
import unittest

from http import HTTPStatus
from unittest.mock import patch

from flask_azure_oauth import FlaskAzureOauth
from flask_azure_oauth.mocks.keys import TestJwk
from flask_azure_oauth.mocks.tokens import TestJwt

from examples import create_app


class AppTestCase(unittest.TestCase):
    def setUp(self):
        self.test_jwks = TestJwk()

        with patch.object(FlaskAzureOauth, "_get_jwks") as mocked_get_jwks:
            mocked_get_jwks.return_value = self.test_jwks.jwks()

            # `self.app` should be set to a Flask application, either by direct import, or by calling an app factory
            self.app = create_app()

            self.app.config["TEST_JWKS"] = self.test_jwks
            self.app_context = self.app.app_context()
            self.app_context.push()
            self.client = self.app.test_client()

    def test_protected_route_with_multiple_scopes_authorised(self):
        # Generate token with required roles
        token = TestJwt(
            app=self.app, roles=["BAS.MAGIC.ADD.Records.Publish.All", "BAS.MAGIC.ADD.Records.ReadWrite.All"]
        )

        # Make request to protected route with token
        response = self.client.get(
            "/protected-with-multiple-scopes", headers={"authorization": f"bearer { token.dumps() }"}
        )
        self.assertEqual(HTTPStatus.OK, response.status_code)
        self.app_context.pop()

    def test_protected_route_with_multiple_scopes_unauthorised(self):
        # Generate token with no scopes
        token = TestJwt(app=self.app)

        # Make request to protected route with token
        response = self.client.get(
            "/protected-with-multiple-scopes", headers={"authorization": f"bearer { token.dumps() }"}
        )
        self.assertEqual(HTTPStatus.FORBIDDEN, response.status_code)
        self.app_context.pop()
```

## Developing

This provider is developed as a Python library. A bundled Flask application is used to simulate its usage and act as
framework for running tests etc.

### Development environment

Git and [Poetry](https://python-poetry.org) are required to set up a local development environment of this project.

**Note:** If you use [Pyenv](https://github.com/pyenv/pyenv), this project sets a local Python version for consistency.

```shell
# clone from the BAS GitLab instance if possible
$ git clone https://gitlab.data.bas.ac.uk/web-apps/flask-extensions/flask-azure-oauth.git

# alternatively, clone from the GitHub mirror
$ git clone https://github.com/antarctica/flask-azure-oauth.git

# setup virtual environment
$ cd flask-azure-oauth
$ poetry install
```

### Code Style

PEP-8 style and formatting guidelines must be used for this project, except the 80 character line limit.
[Black](https://github.com/psf/black) is used for formatting, configured in `pyproject.toml` and enforced as part of
[Python code linting](#code-linting).

Black can be integrated with a range of editors, such as
[PyCharm](https://black.readthedocs.io/en/stable/integrations/editors.html#pycharm-intellij-idea), to apply formatting
automatically when saving files.

To apply formatting manually:

```shell
$ poetry run black src/ tests/
```

### Code Linting

[Flake8](https://flake8.pycqa.org) and various extensions are used to lint Python files. Specific checks, and any
configuration options, are documented in the `./.flake8` config file.

To check files manually:

```shell
$ poetry run flake8 src/ examples/
```

Checks are run automatically in [Continuous Integration](#continuous-integration).

### Dependencies

Python dependencies for this project are managed with [Poetry](https://python-poetry.org) in `pyproject.toml`.

Non-code files, such as static files, can also be included in the [Python package](#python-package) using the
`include` key in `pyproject.toml`.

#### Adding new dependencies

To add a new (development) dependency:

```shell
$ poetry add [dependency] (--dev)
```

Then update the Docker image used for CI/CD builds and push to the BAS Docker Registry (which is provided by GitLab):

```shell
$ docker build -f gitlab-ci.Dockerfile -t docker-registry.data.bas.ac.uk/web-apps/flask-extensions/flask-azure-oauth:latest .
$ docker push docker-registry.data.bas.ac.uk/web-apps/flask-extensions/flask-azure-oauth:latest
```

#### Updating dependencies

```shell
$ poetry update
```

See the instructions above to update the Docker image used in CI/CD.

#### Dependency vulnerability checks

The [Safety](https://pypi.org/project/safety/) package is used to check dependencies against known vulnerabilities.

**IMPORTANT!** As with all security tools, Safety is an aid for spotting common mistakes, not a guarantee of secure
code. In particular this is using the free vulnerability database, which is updated less frequently than paid options.

This is a good tool for spotting low-hanging fruit in terms of vulnerabilities. It isn't a substitute for proper
vetting of dependencies, or a proper audit of potential issues by security professionals. If in any doubt you MUST seek
proper advice.

Checks are run automatically in [Continuous Integration](#continuous-integration).

To check locally:

```shell
$ poetry export --without-hashes -f requirements.txt | poetry run safety check --full-report --stdin
```

#### `authlib` package

The `authlib` dependency is locked to version `0.14.3` as the `0.15.x` release series contains a bug that prevents the
`kid` claim from being accessed from Jason Web Key (JWK) instances. This is a known issue and will be resolved in the
`1.x` release. See https://github.com/lepture/authlib/issues/314 for more information.

### Static security scanning

To ensure the security of this API, source code is checked against [Bandit](https://github.com/PyCQA/bandit)
and enforced as part of [Python code linting](#code-linting-python).

**Warning:** Bandit is a static analysis tool and can't check for issues that are only be detectable when running the
application. As with all security tools, Bandit is an aid for spotting common mistakes, not a guarantee of secure code.

To check manually:

```shell
$ poetry run bandit -r src/ examples/
```

**Note:** This package contains a number of testing methods that deliberately do insecure or nonsensical things. These
are necessary to test failure modes and error handling, they are not a risk when using this package as intended. These
workarounds have been exempted from these security checks where they apply.

Checks are run automatically in [Continuous Integration](#continuous-integration).

## Testing

### Integration tests

This project uses integration tests to ensure features work as expected and to guard against regressions and
vulnerabilities.

The Python [UnitTest](https://docs.python.org/3/library/unittest.html) library is used for running tests using Flask's
test framework. Test cases are defined in files within `tests/` and are automatically loaded when using the `test`
Flask CLI command included in the local Flask application in the development environment.

To run tests manually using PyCharm, use the included *App (tests)* run/debug configuration.

To run tests manually:

```shell
$ FLASK_APP=examples FLASK_ENV=testing poetry run python -m unittest discover
```

Tests are ran automatically in [Continuous Integration](#continuous-integration).

### Continuous Integration

All commits will trigger a Continuous Integration process using GitLab's CI/CD platform, configured in `.gitlab-ci.yml`.

### Test/Example applications

For verifying this provider works for real-world use-cases, a test Flask application is included in
`examples/__init__.py`. This test application acts as both an application providing access to, and accessing, protected
resources. It can use a number of application registrations registered in the BAS Web & Applications Test Azure AD.

These applications allow testing different versions of access tokens for example. These applications are intended for
testing only. They do not represent real applications, or contain any sensitive or protected information.

To test requesting resources from protected resources as an API, set the appropriate config options and run the
application container:

```shell
$ FLASK_APP=examples poetry run flask
```

To test requesting resources from protected resources as a browser application, set the appropriate config options and
start the application container:

```shell
$ FLASK_APP=examples poetry run flask run
```

Terraform is used to provision the application registrations used:

```
$ cd provisioning/terraform
$ docker-compose run terraform
$ az login --allow-no-subscriptions
$ terraform init
$ terraform validate
$ terraform apply
```

**Note:** Several properties in the application registration resources require setting once the registration has been
initially made (identifiers for example). These will need commenting out before use.

Some properties, such as client secrets, can only be set once applications have been registered in the Azure Portal.

Terraform state information is held in the BAS Terraform Remote State project (internal).

## Deployment

### Python package

This project is distributed as a Python package, hosted in [PyPi](https://pypi.org/project/flask-azure-oauth).

Source and binary packages are built and published automatically using
[Poetry](https://python-poetry.org) in [Continuous Deployment](#continuous-deployment).

**Note:** Except for tagged releases, Python packages built in CD will use `0.0.0` as a version to indicate they are
not formal releases.

### Continuous Deployment

A Continuous Deployment process using GitLab's CI/CD platform is configured in `.gitlab-ci.yml`.

## Release procedure

For all releases:

1. create a `release` branch
2. bump the version as appropriate in `pyproject.toml`
3. close release in `CHANGELOG.md`
4. push changes, merge the `release` branch into `main`, and tag with version

The project will be built and published to PyPi automatically through [Continuous Deployment](#continuous-deployment).

## Feedback

The maintainer of this project is the BAS Web & Applications Team, they can be contacted at:
[servicedesk@bas.ac.uk](mailto:servicedesk@bas.ac.uk).

## Issue tracking

This project uses issue tracking, see the
[Issue tracker](https://gitlab.data.bas.ac.uk/web-apps/flask-extensions/flask-azure-oauth/issues) for more information.

**Note:** Read & write access to this issue tracker is restricted. Contact the project maintainer to request access.

## License

Copyright (c) 2019-2022 UK Research and Innovation (UKRI), British Antarctic Survey.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
