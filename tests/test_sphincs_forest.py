import pytest
from spyncs_plus.components.sphincs_forest.secret import SphincsForestSecret, SphincsForestSecretKey
from spyncs_plus.helpers.hashers.sha256 import SHA256Hasher
from spyncs_plus.helpers.key_generators.csprng import CSPRNGKeyGenerator

@pytest.fixture
def forest_secret(pytestconfig: pytest.Config) -> tuple[SphincsForestSecret, SphincsForestSecretKey]:
    secret = pytestconfig.cache.get("secret_generator", None)
    pk = pytestconfig.cache.get("secret_key", None)
    if secret is None:
        secret = SphincsForestSecret(SHA256Hasher(), CSPRNGKeyGenerator(), 123)
    if pk is None:
        pk = secret.get_secret_key(8)
    return secret, pk

@pytest.fixture
def forest_secret_modified(pytestconfig: pytest.Config) -> tuple[SphincsForestSecret, SphincsForestSecretKey]:
    secret = pytestconfig.cache.get("secret_generator", None)
    pk = pytestconfig.cache.get("secret_key", None)
    if secret is None:
        secret = SphincsForestSecret(SHA256Hasher(), CSPRNGKeyGenerator(), 123, 16, 4)
    if pk is None:
        pk = secret.get_secret_key(20)
    return secret, pk


def test_signature(forest_secret: tuple[SphincsForestSecret, SphincsForestSecretKey]):
    secret, pk = forest_secret
    assert pk._last_level_size == 4
    
    message = b'Hello World'
    signature = pk.sign(message)
    
    assert signature.hash.hex() == "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e"
    assert signature.signature.verify()
    assert secret.hasher.concatenate_hash(signature.signature.signature).hex() == "70fa05759a28cffa08cb399d9b9194c25ee6f8702d10db325f3de3fd505dbc7f"


def test_signature_for_modified(forest_secret_modified: tuple[SphincsForestSecret, SphincsForestSecretKey]):
    secret, pk = forest_secret_modified
    assert pk._last_level_size == 16

    message = b'Hello World'
    signature = pk.sign(message)
    
    assert signature.hash.hex() == "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e"
    assert signature.signature.verify()
    assert secret.hasher.concatenate_hash(signature.signature.signature).hex() == "f4c7118e4a737fccfcd296ae473a3cdee430cd6e616f807452fb02e28398367d"


def test_forest_key_generation(forest_secret: tuple[SphincsForestSecret, SphincsForestSecretKey]):
    # this is for local testing purpose
    secret, pk = forest_secret
    assert secret._keys_to_generate_per_tree == 136
    assert all(k.is_level_up_signed() for k in pk.levels[:-1])
    assert pk.levels[-1].is_level_up_signed() == False

    level_o_pub_key = pk.levels[-1].public_key.hex()
    level_1_pub_key = pk.levels[-2].public_key.hex()
    assert level_o_pub_key != level_1_pub_key

    pk = secret.get_secret_key(2**15)
    assert all(k.is_level_up_signed() for k in pk.levels[:-1])
    assert pk.levels[-1].is_level_up_signed() == False

    assert pk.levels[-1].public_key.hex() == level_o_pub_key
    assert pk.levels[-2].public_key.hex() == level_1_pub_key
    
    pk = secret.get_secret_key(4950368079037995815)
    assert all(k.is_level_up_signed() for k in pk.levels[:-1])
    assert pk.levels[-1].is_level_up_signed() == False

    assert pk.levels[-1].public_key.hex() == level_o_pub_key
    assert pk.levels[-2].public_key.hex() != level_1_pub_key


    secret = SphincsForestSecret(SHA256Hasher(), CSPRNGKeyGenerator(), 124)
    pk = secret.get_secret_key(8)

    assert all(k.is_level_up_signed() for k in pk.levels[:-1])
    assert pk.levels[-1].is_level_up_signed() == False
    assert pk.levels[-1].public_key.hex() != level_o_pub_key # Generated a diffrent public key

def test_forest_modefied_structure_keygen(forest_secret_modified: tuple[SphincsForestSecret, SphincsForestSecretKey]):
    # this is for local testing purpose
    secret, pk = forest_secret_modified
    assert secret._keys_to_generate_per_tree == 544

    assert all(k.is_level_up_signed() for k in pk.levels[:-1])
    assert pk.levels[-1].is_level_up_signed() == False

    level_o_pub_key = pk.levels[-1].public_key.hex()
    level_1_pub_key = pk.levels[-2].public_key.hex()
    assert level_o_pub_key != level_1_pub_key

    pk = secret.get_secret_key(4950368079037995815)
    assert all(k.is_level_up_signed() for k in pk.levels[:-1])
    assert pk.levels[-1].is_level_up_signed() == False

    assert pk.levels[-1].public_key.hex() == level_o_pub_key
    assert pk.levels[-2].public_key.hex() != level_1_pub_key
