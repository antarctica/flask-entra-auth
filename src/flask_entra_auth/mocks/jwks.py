from cryptography.hazmat.primitives import serialization
from joserfc.jwk import KeySet
from joserfc.rfc7518.rsa_key import RSAKey


class MockJwk:
    """
    Mock JSON Web Key.

    For use in application testing where real keys can't be used.
    """

    def __init__(self, key: RSAKey):
        self._jwk = key

    @property
    def kid(self) -> str:
        """Key ID."""
        return self._jwk.kid

    @property
    def private_key(self) -> bytes:
        """OpenSSL PEM formatted private key for signing tokens."""
        return self._jwk.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )


class MockJwks:
    """
    Mock JSON Web Key Set.

    For use in application testing where real keys can't be used.
    """

    def __init__(self):
        """Initialise key set with a random key."""
        self._jwks = KeySet.generate_key_set(key_type="RSA", crv_or_size=2048, count=1)

    @property
    def keys(self) -> list[RSAKey]:
        """Keys in key set."""
        return self._jwks.keys

    @property
    def jwk(self) -> MockJwk:
        """JSON Web Key."""
        return MockJwk(self._jwks.keys[0])

    def as_dict(self, private: bool = False) -> dict:
        """Key set as dict for use in JWKS endpoints."""
        return self._jwks.as_dict(private=private)
