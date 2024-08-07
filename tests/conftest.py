import pytest
from flask import Flask
from flask.testing import FlaskClient

from flask_azure.__main__ import app as app_


@pytest.fixture()
def fx_app() -> Flask:
    app_.config.update({
        "TESTING": True,
    })

    yield app_


@pytest.fixture()
def fx_app_client(fx_app) -> FlaskClient:
    return fx_app.test_client()
