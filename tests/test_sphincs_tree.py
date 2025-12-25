from spyncs_plus.components.shpincs_tree.proof import SphincsTreeProof
from spyncs_plus.components.shpincs_tree.secret import SphincsTreeSecret
from spyncs_plus.helpers.hashers.sha256 import SHA256Hasher
from spyncs_plus.helpers.random_generators.csprng import CSPRNGRandomGenerator


def test_sphincs_tree():

    private_key = 123
    generator = CSPRNGRandomGenerator().setup(private_key)
    generator.set_cursor(0)

    f = SphincsTreeSecret(SHA256Hasher(), generator)
    i = 0
    proof = f.sign(b'Hello world', i)

    assert proof.verify()

    f_down = SphincsTreeSecret(SHA256Hasher(), generator)
    assert f_down.is_level_up_signed() is False
    f.sign_level_down(f_down, 3)
    proof = f_down.level_up_proof
    assert proof.verify()

    bytes_proof = proof.to_bytes()

    assert SphincsTreeProof.from_bytes(bytes_proof).verify()
    assert f_down.level_up_proof.public_key.hex() == '53f48dc43cf95870477454e3b308174f2ad54d35637a9853d5b621ec91d28ff3'
    assert f_down.is_level_up_signed()