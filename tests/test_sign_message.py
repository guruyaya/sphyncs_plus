import pytest

from spyncs_plus.components.sphincs_forest.secret import SphincsForestSecretGenerator, SphincsForestSecretKey
from spyncs_plus.helpers.hashers.sha256 import SHA256Hasher
from spyncs_plus.helpers.key_generators.csprng import CSPRNGKeyGenerator

@pytest.fixture
def forest_secret(pytestconfig: pytest.Config) -> tuple[SphincsForestSecretGenerator, SphincsForestSecretKey]:
    generator = pytestconfig.cache.get("secret_generator", None)
    secret_key = pytestconfig.cache.get("secret_key", None)
    if generator is None:
        generator = SphincsForestSecretGenerator(SHA256Hasher(), CSPRNGKeyGenerator(), 123)
    if secret_key is None:
        secret_key = generator.get_secret_key(8)
    return generator, secret_key

def test_sign_message(forest_secret):
    _, secret_key = forest_secret
    message = b"Hello World!"
    wrong_message = b"Hello world!"

    signature = secret_key.sign(message)

    assert signature.verify(message)
    assert signature.verify(wrong_message) == False

    assert signature.verify(message, ignore_wrong_hash=True)
    assert signature.verify(wrong_message, ignore_wrong_hash=True) == False