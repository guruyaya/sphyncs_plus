from spyncs_plus.components.shpincs_tree.proof import SphincsTreeProof
from spyncs_plus.components.shpincs_tree.secret import SphincsTreeSecret
from spyncs_plus.helpers.hashers.sha256 import SHA256Hasher
from spyncs_plus.helpers.key_generators.csprng import CSPRNGKeyGenerator


# def test_sphincs_tree():

#     private_key = 123
#     generator = CSPRNGKeyGenerator().setup(private_key)
#     generator.set_cursor(0)

#     f = SphincsTreeSecret(SHA256Hasher(), generator)
#     i = 0
#     proof = f.sign(b'Hello world', i)

#     assert proof.verify()

#     generator.reset_seed()
#     f_down = SphincsTreeSecret(SHA256Hasher(), generator)
#     assert f_down.is_level_up_signed() is False
#     f.sign_level_down(f_down, 3)
#     proof = f_down.level_up_proof
#     assert proof.verify()

#     bytes_proof = proof.to_bytes()

#     assert SphincsTreeProof.from_bytes(bytes_proof).verify()
#     assert f_down.level_up_proof.public_key.hex() == '64df436584c3df34f01afe7f9796997a27e44726f13930be5ad855c7b4beeb0b'
#     assert f_down.is_level_up_signed()