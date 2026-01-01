from spyncs_plus.components.sphincs_forest.secret import SphincsForestSecret
from spyncs_plus.helpers.hashers.sha256 import SHA256Hasher
from spyncs_plus.helpers.key_generators.csprng import CSPRNGKeyGenerator

def test_forest():
    # this is for local testing purpose
    secret = SphincsForestSecret(SHA256Hasher(), CSPRNGKeyGenerator(), 123)
    assert secret._keys_to_generate_per_tree == 544

    pk = secret.get_private_key(8)
    assert all(k.is_level_up_signed() for k in pk[:-1])
    assert pk[-1].is_level_up_signed() == False

    level_o_pub_key = pk[-1].public_key.hex()
    level_1_pub_key = pk[-2].public_key.hex()
    assert level_o_pub_key != level_1_pub_key

    # this is for local testing purpose
    secret = SphincsForestSecret(SHA256Hasher(), CSPRNGKeyGenerator(), 123)
    assert secret._keys_to_generate_per_tree == 544

    pk = secret.get_private_key(2**15)
    assert all(k.is_level_up_signed() for k in pk[:-1])
    assert pk[-1].is_level_up_signed() == False

    assert pk[-1].public_key.hex() == level_o_pub_key
    assert pk[-2].public_key.hex() == level_1_pub_key
    
    
    secret = SphincsForestSecret(SHA256Hasher(), CSPRNGKeyGenerator(), 123)
    assert secret._keys_to_generate_per_tree == 544

    pk = secret.get_private_key(4950368079037995815)
    assert all(k.is_level_up_signed() for k in pk[:-1])
    assert pk[-1].is_level_up_signed() == False

    assert pk[-1].public_key.hex() == level_o_pub_key
    assert pk[-2].public_key.hex() != level_1_pub_key


    secret = SphincsForestSecret(SHA256Hasher(), CSPRNGKeyGenerator(), 124)
    pk = secret.get_private_key(8)

    assert all(k.is_level_up_signed() for k in pk[:-1])
    assert pk[-1].is_level_up_signed() == False
    assert pk[-1].public_key.hex() != level_o_pub_key # Generated a diffrent public key
