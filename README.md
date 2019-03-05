# Flask Azure AD OAuth Provider

Python Flask extension for using Azure Active Directory with OAuth to protect applications

## Purpose

This provider defines an [AuthLib](https://authlib.org) 
[Resource Protector](https://docs.authlib.org/en/latest/flask/2/resource-server.html) to authenticate and authorise 
users and other applications to access features or resources within a Flask application using the OAuth functionality
provided by [Azure Active Directory](https://azure.microsoft.com/en-us/services/active-directory/) as part of the
[Microsoft identity platform](https://docs.microsoft.com/en-us/azure/active-directory/develop/about-microsoft-identity-platform).

This provider depends on Azure Active Directory, acting as a identity provider, to issue 
[OAuth access tokens](https://docs.microsoft.com/en-us/azure/active-directory/develop/access-tokens) which contain the 
identity of a user or application and any permissions they have been assigned through the Azure Portal and management
APIs. These permissions are declared in Azure Active Directory 
[application registrations](https://docs.microsoft.com/en-us/azure/active-directory/develop/app-objects-and-service-principals).

This provider enables Flask applications, acting as service providers, to validate access tokens to check the identity 
of the user or application (authentication), and the permissions required to access the Flask route being accessed.

Specifically this provider supports these scenarios:

1. *application to application* 
   * supports authentication and authorisation
   * used to allow a client application access to some functionality or resources in another application
   * can be used to allow background tasks between applications where a user is not routinely involved (e.g. a nightly 
    data synchronisation)
   * uses the identity of the application acting as a client for authentication
   * uses the permissions assigned to the application acting as a client for authorisation
   * based on the [Client Credentials](https://tools.ietf.org/html/rfc6749#section-4.4) OAuth2 grant type
   * [Azure documentation](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-client-creds-grant-flow)

Other scenarios may be added in future versions of this provider.

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
app.config['AZURE_OAUTH_CLIENT_APPLICATION_IDS'] = ['xxx']

app.auth = TestFlaskAzureOauth(
  azure_tenancy_id=app.config['AZURE_OAUTH_TENANCY'],
  azure_application_id=app.config['AZURE_OAUTH_APPLICATION_ID'],
  azure_client_application_ids=app.config['AZURE_OAUTH_CLIENT_APPLICATION_IDS']
)

@app.route('/unprotected')
def unprotected():
    return 'hello world'

@app.route('/protected')
@app.auth()
def protected():
    return 'hello authenticated entity'

@app.route('/protected-with-single-scope')
@app.auth('required-scope')
def protected():
    return 'hello authenticated and authorised entity'

@app.route('/protected-with-multiple-scope')
@app.auth('required-scope1 required-scope2')
def protected():
    return 'hello authenticated and authorised entity'
```

When the decorator (`app.auth` in this example) is used by itself any authenticated user or application will be able to
access the decorated route. See the `/protected` route above for an example.

To require one or more [Scopes](permissions-roles-and-scopes), add them to the decorator call. Only users or 
applications with all of the scopes specified will be able to access the decorated route. See the 
`/protected-with-single-scope` and `/protected-with-multiple-scopes` routes above for examples.

### Configuration options

The resource protector requires some configuration options to validate tokens correctly. These are typically taken from 
a [Flask config object](http://flask.pocoo.org/docs/1.0/config/):

| Configuration Option           | Data Type | Required | Description                                                                                                               |
| ------------------------------ | --------- | -------- | ------------------------------------------------------------------------------------------------------------------------- |
| `azure_tenancy_id`             | Str       | Yes      | ID of the Azure AD tenancy applications and users are registered within                                                   |
| `azure_application_id`         | Str       | Yes      | ID of the Azure AD application registration representing the application being protected                                  |
| `azure_client_application_ids` | List[Str] | Yes      | IDs of the Azure AD application registrations representing applications granted access to the application being protected |  
| `azure_jwks`                   | Dict      | No       | Optionally, a [JSON Web Key Set](https://tools.ietf.org/html/rfc7517#section-5) used to validate access tokens            |

**Note:** The `azure_jwks` option is typically not used as a current JWKS will be retrieved automatically from the AD 
tenancy's well-known OpenID Connect configuration endpoint.

### Permissions, roles and scopes

...

## Developing

A docker container ran through Docker Compose is used as a development environment for this project. It includes 
development only dependencies listed in `requirements.txt`, a local Flask application in `app.py` and 
[Integration tests](#integration-tests).

Ensure classes and methods are defined within the `flask_azure_oauth` package.

Ensure [Integration tests](#integration-tests) are written for any new feature, or changes to existing features.

If you have access to the BAS GitLab instance, pull the Docker image from the BAS Docker Registry:

```shell
$ docker login docker-registry.data.bas.ac.uk
$ docker-compose pull

# To run the local Flask application using the Flask development server
$ docker-compose up

# To start a shell
$ docker-compose run app ash
```

### Code Style

PEP-8 style and formatting guidelines must be used for this project, with the exception of the 80 character line limit.

[Flake8](http://flake8.pycqa.org/) is used to ensure compliance, and is ran on each commit through 
[Continuous Integration](#continuous-integration).

To check compliance locally:

```shell
$ docker-compose run app flake8 . --ignore=E501
```

### Dependencies

Development Python dependencies should be declared in `requirements.txt` to be included in the development environment.

Runtime Python dependencies should be declared in `requirements.txt` and `setup.py` to also be installed as dependencies
of this package in other applications.

All dependencies should be periodically reviewed and update as new versions are released.

```shell
$ docker-compose run app ash
$ pip install [dependency]==
# this will display a list of available versions, add the latest to `requirements.txt` and or `setup.py`
$ exit
$ docker-compose down
$ docker-compose build
```

If you have access to the BAS GitLab instance, push the Docker image to the BAS Docker Registry:

```shell
$ docker login docker-registry.data.bas.ac.uk
$ docker-compose push
```

### Dependency vulnerability scanning

To ensure the security of this API, all dependencies are checked against 
[Snyk]() for vulnerabilities. 

**Warning:** Snyk relies on known vulnerabilities and can't check for issues that are not in it's database. As with all 
security tools, Snyk is an aid for spotting common mistakes, not a guarantee of secure code.

Some vulnerabilities have been ignored in this project, see `.snyk` for definitions and the 
[Dependency exceptions](#dependency-vulnerability-exceptions) section for more information.

Through [Continuous Integration](#continuous-integration), on each commit current dependencies are tested and a snapshot
uploaded to Snyk. This snapshot is then monitored for vulnerabilities.

#### Dependency vulnerability exceptions

This project contains known vulnerabilities that have been ignored for a specific reason.

* [Py-Yaml `yaml.load()` function allows Arbitrary Code Execution](https://snyk.io/vuln/SNYK-PYTHON-PYYAML-42159)
    * currently no known or planned resolution
    * indirect dependency, required through the `bandit` package
    * severity is rated *high*
    * risk judged to be *low* as we don't use the Yaml module in this application
    * ignored for 1 year for re-review

### Static security scanning

To ensure the security of this API, source code is checked against [Bandit](https://github.com/PyCQA/bandit) for issues 
such as not sanitising user inputs or using weak cryptography. 

**Warning:** Bandit is a static analysis tool and can't check for issues that are only be detectable when running the 
application. As with all security tools, Bandit is an aid for spotting common mistakes, not a guarantee of secure code.

Through [Continuous Integration](#continuous-integration), each commit is tested.

To check locally:

```shell
$ docker-compose run app bandit -r .
```

## Testing

### Integration tests

This project uses integration tests to ensure features work as expected and to guard against regressions and 
vulnerabilities.

The Python [UnitTest](https://docs.python.org/3/library/unittest.html) library is used for running tests using Flask's 
test framework. Test cases are defined in files within `tests/` and are automatically loaded when using the 
`test` Flask CLI command included in the local Flask application in the development environment.

Tests are automatically ran on each commit through [Continuous Integration](#continuous-integration).

To run tests manually:

```shell
$ docker-compose run -e FLASK_ENV=testing app flask test
```

To run tests using PyCharm:

* *Run* -> *Edit Configurations*
* *Add New Configuration* -> *Python Tests* -> *Unittests*

In *Configuration* tab:

* Script path: `[absolute path to project]/tests`
* Python interpreter: *Project interpreter* (*app* service in project Docker Compose)
* Working directory: `[absolute path to project]`
* Path mappings: `[absolute path to project]=/usr/src/app`

**Note:** This configuration can be also be used to debug tests (by choosing *debug* instead of *run*).

### Continuous Integration

All commits will trigger a Continuous Integration process using GitLab's CI/CD platform, configured in `.gitlab-ci.yml`.

This process will run the application [Integration tests](#integration-tests).

Pip dependencies are also [checked and monitored for vulnerabilities](#dependency-vulnerability-scanning).

## Distribution
 
Both source and binary versions of the package are build using [SetupTools](https://setuptools.readthedocs.io), which 
can then be published to the [Python package index](https://pypi.org/project/flask-azure-oauth/) for use in other 
applications. Package settings are defined in `setup.py`.

This project is built and published to PyPi automatically through [Continuous Deployment](#continuous-deployment).

To build the source and binary artefacts for this project manually:

```shell
$ docker-compose run app ash
# build package to /build, /dist and /flask_azure_oauth.egg-info
$ python setup.py sdist bdist_wheel
$ exit
$ docker-compose down
```

To publish built artefacts for this project manually to [PyPi testing](https://test.pypi.org):

```shell
$ docker-compose run app ash
$ python -m twine upload --repository-url https://test.pypi.org/legacy/ dist/*
# project then available at: https://test.pypi.org/project/flask-azure-oauth/
$ exit
$ docker-compose down
```

To publish manually to [PyPi](https://pypi.org):

```shell
$ docker-compose run app ash
$ python -m twine upload --repository-url https://pypi.org/legacy/ dist/*
# project then available at: https://pypi.org/project/flask-azure-oauth/
$ exit
$ docker-compose down
```

### Continuous Deployment

A Continuous Deployment process using GitLab's CI/CD platform is configured in `.gitlab-ci.yml`. This will:

* build the source and binary artefacts for this project
* publish built artefacts for this project to the relevant PyPi repository

This process will deploy changes to [PyPi testing](https://test.pypi.org) on all commits to the *master* branch.

This process will deploy changes to [PyPi](https://pypi.org) on all tagged commits.

## Release procedure

### At release

1. create a `release` branch
2. remove `.dev{ os.getenv('CI_PIPELINE_ID') or None }` from the version parameter in `setup.py` and ensure version 
   is bumped as per semver
3. close release in `CHANGELOG.md`
4. push changes, merge the `release` branch into `master` and tag with version

The project will be built and published to PyPi automatically through [Continuous Deployment](#continuous-deployment).

### After release

1. create a `next-release` branch
2. bump the version parameter in `setup.py` and append `.dev{ os.getenv('CI_PIPELINE_ID') or None }` to signify a     
  pre-release
3. push changes and merge the `next-release` branch into `master`

## Feedback

The maintainer of this project is the BAS Web & Applications Team, they can be contacted at: 
[servicedesk@bas.ac.uk](mailto:servicedesk@bas.ac.uk).

## Issue tracking

This project uses issue tracking, see the 
[Issue tracker](https://gitlab.data.bas.ac.uk/web-apps/flask-extensions/flask-azure-oauth/issues) for more information.

**Note:** Read & write access to this issue tracker is restricted. Contact the project maintainer to request access.

## License

© UK Research and Innovation (UKRI), 2019, British Antarctic Survey.

You may use and re-use this software and associated documentation files free of charge in any format or medium, under 
the terms of the Open Government Licence v3.0.

You may obtain a copy of the Open Government Licence at http://www.nationalarchives.gov.uk/doc/open-government-licence/
