from dataclasses import asdict

from werkzeug.test import TestResponse


def _assert_entra_error(error: callable, response: TestResponse, **kwargs: str) -> None:
    error_ = error(**kwargs)
    assert response.json == asdict(error_.problem)
    assert response.status_code == error_.problem.status
