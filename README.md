# Flask Azure AD OAuth Provider

Python Flask extension for securing apps with Azure Active Directory OAuth

## Purpose

This provider defines an [AuthLib](https://authlib.org) 
[Resource Protector](https://docs.authlib.org/en/latest/flask/2/resource-server.html) to authenticate and authorise 
users and other applications to access features or resources within a Flask application using the OAuth functionality
offered by [Azure Active Directory](https://azure.microsoft.com/en-us/services/active-directory/), as part of the
[Microsoft identity platform](https://docs.microsoft.com/en-us/azure/active-directory/develop/about-microsoft-identity-platform).

This provider depends on Azure Active Directory, which acts as a identity provider, to issue 
[OAuth access tokens](https://docs.microsoft.com/en-us/azure/active-directory/develop/access-tokens). These contain 
various claims including the identity of the user and client application (used for authentication) and any permissions 
assigned or delegated to the user or application (used for authorisation).

This provider will validate and interpret information in these tokens to restrict access to parts of a Flask app.

Specifically this provider supports these scenarios:

1. *application to application* 
   * supports authentication and authorisation
   * used to allow a client application access to some functionality or resources provided by another application
   * can be used for non-interactive, machine-to-machine, processes (using the OAuth Client Credentials Grant)
   * uses the identity of the client application for authentication
   * optionally, uses permissions assigned directly to the client application for authorisation
2. *user to application*
    * supports authentication and authorisation
    * used to allow users access to some functionality or resources provided by another application
    * can be used for interactive console (using the Device Authorization Grant) or web application (using the OAuth 
      Authorization Code Grant) processes
    * uses the identity of the user, and optionally, the client application they are using, for authentication
    * optionally, uses permissions assigned to the user, permissions delegated by the user to the client application, 
      and/or permissions assigned directly to the client application for authorisation

Other scenarios may be added in future versions of this provider.

**Note:** This provider does not support client applications requesting tokens from Azure. See the 
[Microsoft Authentication Library (MSAL) for Python](https://github.com/AzureAD/microsoft-authentication-library-for-python)
if you need to do this.

## Installation

This package can be installed using Pip from [PyPi](https://pypi.org/project/flask-azure-oauth):

```
$ pip install flask-azure-oauth
```

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

Independently of these options, it's possibly to whitelist specific, allowed, client applications, regardless of the 
user using them. This is useful in circumstances where a user may be authorised but the client can't be trusted.:

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
| `AZURE_OAUTH_CLIENT_APPLICATION_IDS` | List[Str] | Yes      | ID(s) of the Azure AD application registration(s) for the application(s) granted access to the application being protected |  

Before these options can be set you will need to:

1. [register the application to be protected](#registering-an-application-in-azure)
2. [define the permissions and roles this application supports](#defining-permissions-and-roles-within-an-application)
3. [register the application(s) that will use the protected application](#registering-an-application-in-azure)
4. [assign permissions to users and/or client application(s)](#assigning-permissions-and-roles-to-users-and-applications)

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

* applications are represented by [Application registrations]()
* users are represented by [users]()

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

For assigning permissions permissions:

* permissions can be delegated to client applications, with the agreement of the current user
* permissions can be directly assigned to client applications, with the agreement of a tenancy administrator

**Note:** Direct assignment is needed for non-interactive applications, such as daemons.

#### Registering an application in Azure

[Follow these instructions](https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app).

**Note:** These instructions apply both to applications that protected by this provider (protected applications), and 
those that will be granted access to use such applications, possibly by a user (client applications).

### Testing support

When a Flask application is in testing mode (i.e. `app.config['TESTING']=True`), this provider will generate a local 
JSON Web Key Set, containing a single key, which can be used to sign tokens with arbitrary scopes.

This can be used to test routes that require a scope or scopes, by allowing tokens to be generated with or without 
required scopes to test both authorised and unauthorised responses.

Typically the instance of this provider will be defined outside of an application, and therefore persist between 
application instances and tests.

For example:

```python
import unittest

from http import HTTPStatus
from flask_azure_oauth.tokens import TestJwt


class AppTestCase(unittest.TestCase):
    def setUp(self):
        # 'create_app()' should return a Flask application where `app.config['TESTING'] = True` has been set
        self.app = create_app('testing')
        self.app_context = self.app.app_context()
        self.app_context.push()
        self.client = self.app.test_client()

    def test_protected_route_with_multiple_scopes_authorised(self):
        # Generate token with required roles
        token = TestJwt(app=self.app, roles=['required-scope1', 'required-scope2'])
        
        # Make request to protected route with token
        response = self.client.get(
            '/protected-with-multiple-scopes',
            headers={'authorization': f"bearer { token }"}
        )
        self.assertEqual(HTTPStatus.OK, response.status_code)
        self.app_context.pop()
    
    def test_protected_route_with_multiple_scopes_unauthorised(self):
        # Generate token with no scopes
        token = TestJwt(app=self.app)
        
        # Make request to protected route with token
        response = self.client.get(
            '/protected-with-multiple-scopes',
            headers={'authorization': f"bearer { token }"}
        )
        self.assertEqual(HTTPStatus.FORBIDDEN, response.status_code)
        self.app_context.pop()
```

## Developing

This project is developed as a Python library. A bundled Flask application is used to simulate its usage and to act as
framework for running tests etc.

```shell
$ git clone https://gitlab.data.bas.ac.uk/web-apps/flask-extensions/flask-azure-oauth.git
$ cd flask-azure-oauth
```

### Development environment

Docker and Docker Compose are required to setup a local development environment of this application.

If you have access to the [BAS GitLab instance](https://gitlab.data.bas.ac.uk), you can pull the application Docker
image from the BAS Docker Registry. Otherwise you will need to build the Docker image locally.

```shell
# If you have access to gitlab.data.bas.ac.uk:
$ docker login docker-registry.data.bas.ac.uk
$ docker-compose pull
# If you don't have access:
$ docker-compose build
```

### Code Style

PEP-8 style and formatting guidelines must be used for this project, with the exception of the 80 character line limit.

[Black](https://github.com/psf/black) is used to ensure compliance, configured in `pyproject.toml`.

Black can be [integrated](https://black.readthedocs.io/en/stable/editor_integration.html#pycharm-intellij-idea) with a
range of editors, such as PyCharm, to perform formatting automatically.

To apply formatting manually:

```shell
$ docker-compose run app black flask_azure_oauth/
```

To check compliance manually:

```shell
$ docker-compose run app black --check flask_azure_oauth/
```

Checks are ran automatically in [Continuous Integration](#continuous-integration).

### Dependencies

Python dependencies for this project are managed with [Poetry](https://python-poetry.org) in `pyproject.toml`.

Non-code files, such as static files, can also be included in the [Python package](#python-package) using the
`include` key in `pyproject.toml`.

To add a new (development) dependency:

```shell
$ docker-compose run app ash
$ poetry add [dependency] (--dev)
```

Then rebuild the development container, and if you can, push to GitLab:

```shell
$ docker-compose build app
$ docker-compose push app
```

### Supported Python versions

This project is only tested against the Python version used in the project container.

Other Python versions may be compatible with this project but these are not tested or officially supported.

A minimum Python version is set in `pyproject.toml`.

### Static security scanning

To ensure the security of this API, source code is checked against [Bandit](https://github.com/PyCQA/bandit) for issues 
such as not sanitising user inputs or using weak cryptography. 

**Warning:** Bandit is a static analysis tool and can't check for issues that are only be detectable when running the 
application. As with all security tools, Bandit is an aid for spotting common mistakes, not a guarantee of secure code.

To check manually from the command line:

```shell
$ docker-compose run app bandit -r .
```

Checks are ran automatically in [Continuous Integration](#continuous-integration).

## Testing

### Integration tests

This project uses integration tests to ensure features work as expected and to guard against regressions and 
vulnerabilities.

The Python [UnitTest](https://docs.python.org/3/library/unittest.html) library is used for running tests using Flask's 
test framework. Test cases are defined in files within `tests/` and are automatically loaded when using the `test` 
Flask CLI command included in the local Flask application in the development environment.

To run tests manually:

```shell
$ docker-compose run -e FLASK_ENV=testing app flask test --test-runner text
```

To run tests manually using PyCharm, use the included *App (Tests)* run/debug configuration.

Tests are ran automatically in [Continuous Integration](#continuous-integration).

### Continuous Integration

All commits will trigger a Continuous Integration process using GitLab's CI/CD platform, configured in `.gitlab-ci.yml`.

## Deployment

### Python package

This project is distributed as a Python package, hosted in [PyPi](https://pypi.org/project/flask-azure-oauth).

Source and binary packages are built and published automatically using
[Poetry](https://python-poetry.org/docs/cli/#publish) in [Continuous Delivery](#continuous-deployment).

Package versions are determined automatically using the `support/python-packaging/parse_version.py` script.

### Continuous Deployment

A Continuous Deployment process using GitLab's CI/CD platform is configured in `.gitlab-ci.yml`.

## Release procedure

For all releases:

1. create a `release` branch
2. close release in `CHANGELOG.md`
3. push changes, merge the `release` branch into `master` and tag with version

The project will be built and published to PyPi automatically through [Continuous Deployment](#continuous-deployment).

## Feedback

The maintainer of this project is the BAS Web & Applications Team, they can be contacted at: 
[servicedesk@bas.ac.uk](mailto:servicedesk@bas.ac.uk).

## Issue tracking

This project uses issue tracking, see the 
[Issue tracker](https://gitlab.data.bas.ac.uk/web-apps/flask-extensions/flask-azure-oauth/issues) for more information.

**Note:** Read & write access to this issue tracker is restricted. Contact the project maintainer to request access.

## License

© UK Research and Innovation (UKRI), 2019 - 2020, British Antarctic Survey.

You may use and re-use this software and associated documentation files free of charge in any format or medium, under 
the terms of the Open Government Licence v3.0.

You may obtain a copy of the Open Government Licence at http://www.nationalarchives.gov.uk/doc/open-government-licence/
