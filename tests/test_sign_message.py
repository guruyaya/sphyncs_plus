import pytest

from spyncs_plus.components.sphincs_forest.secret import SphincsForestSecretGenerator, SphincsForestSecretKey
from spyncs_plus.helpers.hashers.sha256 import SHA256Hasher
from spyncs_plus.helpers.key_generators.csprng import CSPRNGKeyGenerator

def test_sign_message():
    generator = SphincsForestSecretGenerator(SHA256Hasher(), CSPRNGKeyGenerator(), 123)
    secret_key = generator.get_secret_key(8)
    message = b"Hello World!"
    wrong_message = b"Hello world!"

    signature = secret_key.sign(message)

    assert signature.verify(message)
    assert signature.verify(wrong_message) == False

    assert signature.verify(message, ignore_wrong_hash=True)
    assert signature.verify(wrong_message, ignore_wrong_hash=True) == False