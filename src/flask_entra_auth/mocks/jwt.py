from __future__ import annotations

from datetime import datetime

from jwt import encode as jwt_encode

from flask_entra_auth.mocks.jwks import MockJwk


class MockClaims:
    """Subset of Entra token claims relevant to package tests."""

    def __init__(self, self_app_id: str):
        self._t = datetime.now()  # noqa: DTZ005

        self._iss = "https://issuer.auth.example.com"
        self._sub = "test_subject"
        self._aud = self_app_id
        self._exp = int(self._t.timestamp() + 3600)
        self._nbf = int(self._t.timestamp())
        self._azp = "test_app_2"
        self._ver = "2.0"
        self._scps = ["SCOPE_A", "SCOPE_B", "SCOPE_C"]
        self._roles = ["ROLE_1", "ROLE_2", "ROLE_3"]

    @property
    def iss(self) -> str:
        """Issuer."""
        return self._iss

    @property
    def sub(self) -> str:
        """Subject."""
        return self._sub

    @property
    def aud(self) -> str:
        """Audience."""
        return self._aud

    @property
    def exp(self) -> int:
        """Expiration."""
        return self._exp

    @property
    def nbf(self) -> int:
        """Not Before."""
        return self._nbf

    @property
    def azp(self) -> str:
        """App."""
        return self._azp

    @property
    def ver(self) -> str:
        """Version."""
        return self._ver

    @property
    def scps(self) -> list[str]:
        """Scopes (apps)."""
        return self._scps

    @property
    def roles(self) -> list[str]:
        """Roles (users)."""
        return self._roles


class MockJwtClient:
    """Mock JWT client for generating tokens for testing."""

    def __init__(self, key: MockJwk, claims: MockClaims):
        self._key = key
        self._claims = claims

    def _generate(self, payload: dict, headers: dict | None | bool = None) -> str:
        headers = headers or {"kid": self._key.kid} if not isinstance(headers, bool) else {}
        return jwt_encode(payload=payload, key=self._key.private_key, algorithm="RS256", headers=headers)

    def generate_empty(self) -> str:
        """Create token with no header or claims."""
        return self._generate(payload={}, headers=False)

    def generate_kid(self) -> str:
        """Create token with kid header parameter only."""
        return self._generate(payload={})

    def generate(
        self,
        kid: str | None = None,
        iss: str | bool | None = None,
        sub: str | bool | None = None,
        aud: str | bool | None = None,
        exp: int | bool | None = None,
        nbf: int | bool | None = None,
        azp: str | bool | None = None,
        ver: str | bool | None = None,
        scps: list[str] | bool | None = None,
        roles: list[str] | bool | None = None,
    ) -> str:
        """
        Create token with specified claims and headers.

        Default values are used for claims unless overridden. If overridden with `False`, the claim is omitted.
        """
        headers = {"kid": kid} if kid else {}

        payload = {
            "iss": iss or self._claims.iss if not isinstance(iss, bool) else None,
            "sub": sub or self._claims.sub if not isinstance(sub, bool) else None,
            "aud": aud or self._claims.aud if not isinstance(aud, bool) else None,
            "exp": exp or self._claims.exp if not isinstance(exp, bool) else None,
            "nbf": nbf or self._claims.nbf if not isinstance(nbf, bool) else None,
            "azp": azp or self._claims.azp if not isinstance(azp, bool) else None,
            "ver": ver or self._claims.ver if not isinstance(ver, bool) else None,
            "scps": scps or self._claims.scps if not isinstance(scps, bool) else None,
            "roles": roles or self._claims.roles if not isinstance(roles, bool) else None,
        }
        # remove any keys that have None as values
        payload = {k: v for k, v in payload.items() if v is not None}

        return self._generate(payload=payload, headers=headers)
