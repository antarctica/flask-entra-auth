import random
import string

from authlib.jose import JWK, JWK_ALGORITHMS

# noinspection PyPackageRequirements
from cryptography.hazmat.backends import default_backend
# noinspection PyPackageRequirements
from cryptography.hazmat.primitives import serialization
# noinspection PyPackageRequirements
from cryptography.hazmat.primitives.asymmetric import rsa


class TestJwk:
    """
    Class to create JSON Web Keys (JWKs) for testing purposes

    Supports generating unique RSA 256 bit keys for signing JSON Web Tokens. As the key-pair is unique to each JWK
    instance, this class allows the private key to be retrieved for signing test tokens. Normally this isn't possible.
    """
    _jwk = JWK(algorithms=JWK_ALGORITHMS)

    algorithm = 'RS256'
    key_type = 'RSA'
    key_use = 'sig'

    def __init__(self):
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        self.public_key = self.private_key.public_key()
        self.key_id = 'test-' + ''.join(
            random.choices(string.ascii_lowercase + string.ascii_uppercase + string.digits, k=7)
        )

    def private_key_pem(self) -> str:
        """
        Returns the private key of the unique key-pair generated for the JWK for signing JSON Web Tokens

        The private key is returned in a typical form - i.e. '--- Begin Private Key --- ...'

        :rtype str
        :return: Private key as PEM encoded, OpenSSL formatted, string
        """
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()

    def public_key_pem(self) -> str:
        """
        Returns the public key contained in the JWK, based on the unique key-pair generated for the JWK, for verifying
        JSON Web Tokens

        The public key is returned in a typical form - i.e. '--- Begin Public Key --- ...'

        :rtype str
        :return: Public key as PEM encoded, OpenSSL formatted, string
        """
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

    def kid(self) -> str:
        """
        Returns the Key ID contained in the JWK

        :rtype str
        :return: key ID
        """
        return self.key_id

    def dumps(self) -> dict:
        """
        Returns the JWK as a Python dictionary, suitable for encoding with JSON for exchange

        :rtype: dict
        :return: JWK
        """
        jwk = self._jwk.dumps(self.public_key_pem(), kty=self.key_type, use=self.key_use, kid=self.key_id)

        return jwk

    def jwks(self) -> dict:
        """
        Returns the JWK as a Python dictionary, as part of a JSON Web Key Set (JWKS), suitable for encoding with JSON
        for exchange

        Key sets are used to establish the signing keys that may be used to sign tokens, identified by their Key IDs.

        :rtype dict
        :return: JWK as a JWK Set
        """
        return {'keys': [self.dumps()]}
