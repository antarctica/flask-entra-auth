# Flask Entra Auth - Development Documentation

## Local development environment

Requirements:

* Python 3.9 ([pyenv](https://github.com/pyenv/pyenv) recommended)
* [Poetry](https://python-poetry.org/docs/#installation)
* Git (`brew install git`)
* Pre-commit (`pipx install pre-commit`)

Clone project:

```
$ git clone https://gitlab.data.bas.ac.uk/MAGIC/flask-entra-auth.git
$ cd flask-entra-auth
```

Install project:

```
$ poetry install
```

Install pre-commit hooks:

```
$ pre-commit install
```

## Dependencies

### Vulnerability scanning

The [Safety](https://pypi.org/project/safety/) package is used to check dependencies against known vulnerabilities.

**WARNING!** As with all security tools, Safety is an aid for spotting common mistakes, not a guarantee of secure code.
In particular this is using the free vulnerability database, which is updated less frequently than paid options.

Checks are run automatically in [Continuous Integration](#continuous-integration). To check locally:

```
$ poetry run safety scan
```

## Linting

### Ruff

[Ruff](https://docs.astral.sh/ruff/) is used to lint and format Python files. Specific checks and config options are
set in [`pyproject.toml`](./pyproject.toml). Linting checks are run automatically in
[Continuous Integration](#continuous-integration).

To check linting locally:

```
$ poetry run ruff check src/ tests/
```

To run and check formatting locally:

```
$ poetry run ruff format src/ tests/
$ poetry run ruff format --check src/ tests/
```

### Static security analysis

Ruff is configured to run [Bandit](https://github.com/PyCQA/bandit), a static analysis tool for Python.

**WARNING!** As with all security tools, Bandit is an aid for spotting common mistakes, not a guarantee of secure code.
In particular this tool can't check for issues that are only be detectable when running code.

### Editorconfig

For consistency, it's strongly recommended to configure your IDE or other editor to use the
[EditorConfig](https://editorconfig.org/) settings defined in [`.editorconfig`](./.editorconfig).

### Pre-commit hook

A set of [Pre-Commit](https://pre-commit.com) hooks are configured in
[`.pre-commit-config.yaml`](./.pre-commit-config.yaml). These checks must pass to make a commit.

## Tests

### Pytest

[pytest](https://docs.pytest.org) with a number of plugins is used to test the application. Config options are set in
[`pyproject.toml`](./pyproject.toml). Tests checks are run automatically in
[Continuous Integration](#continuous-integration).

To run tests locally:

```
$ poetry run pytest
```

Tests are ran against an internal Flask app defined in [`tests/app.py`](./tests/app.py).

### Pytest fixtures

Fixtures should be defined in [conftest.py](./tests/conftest.py), prefixed with `fx_` to indicate they are a fixture,
e.g.:

```python
import pytest

@pytest.fixture()
def fx_test_foo() -> str:
    """Example of a test fixture."""
    return 'foo'
```

### Pytest-cov test coverage

[`pytest-cov`](https://pypi.org/project/pytest-cov/) checks test coverage. We aim for 100% coverage but exemptions are fine with good justification:

- `# pragma: no cover` - for general exemptions
- `# pragma: no branch` - where a conditional branch can never be called

To run tests with coverage locally:

```
$ poetry run pytest --cov --cov-report=html
```

Where tests are added to ensure coverage, use the `cov` [mark](https://docs.pytest.org/en/7.1.x/how-to/mark.html), e.g:

```python
import pytest

@pytest.mark.cov
def test_foo():
    assert 'foo' == 'foo'
```

### Continuous Integration

All commits will trigger Continuous Integration using GitLab's CI/CD platform, configured in `.gitlab-ci.yml`.

## Releases

See [README](./README.md#releases).

### Release workflow

Create a [release issue](https://gitlab.data.bas.ac.uk/MAGIC/flask-entra-auth/-/issues/new?issue[title]=x.x.x%20release&issuable_template=release)
and follow the instructions.

GitLab CI/CD will automatically create a GitLab Release based on the tag, including:

- milestone link
- change log extract
- package artefact
- link to README at the relevant tag

GitLab CI/CD will automatically trigger a [Deployment](#deployment) of the new release.

## Deployment

### Python package

This project is distributed as a Python (Pip) package available from [PyPi](https://pypi.org/project/flask-entra-auth/)

The package can also be built manually if needed:

```
$ poetry build
```

### Deployment workflow

[Continuous Deployment](#continuous-deployment) will:

- build this package using Poetry
- upload it to [PyPi](https://pypi.org/project/flask-entra-auth/)

### Continuous Deployment

Tagged commits created for [Releases](./README.md#releases) will trigger Continuous Deployment using GitLab's
CI/CD platform configured in [`.gitlab-ci.yml`](./.gitlab-ci.yml).
