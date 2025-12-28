from random import Random
from spyncs_plus.helpers.key_generators.csprng import CSPRNGKeyGenerator
import pytest # type:ignore

def test_init_csprng():
    rgen = CSPRNGKeyGenerator()
    assert hasattr(rgen, "base_seed") == False
    assert rgen.key_size_bytes == 32
    assert rgen.protocol == "CSPRNG"
    assert rgen.version == "1.0a"
    assert isinstance(rgen._instance, Random)

    generated_random_instance = Random()
    rgen2 = CSPRNGKeyGenerator(generated_random_instance)
    assert rgen2._instance is generated_random_instance
    assert rgen2._instance is not rgen._instance

def test_no_setup_exception():
    rgen = CSPRNGKeyGenerator()
    
    with pytest.raises(CSPRNGKeyGenerator.DidNotRunSetup):
        rgen.reset_seed()
    
    with pytest.raises(CSPRNGKeyGenerator.DidNotRunSetup):
        rgen.set_cursor(1)
    
    with pytest.raises(CSPRNGKeyGenerator.DidNotRunSetup):
        next( rgen.get_keys() )
    
# def test_high_keygen():
#     rgen = CSPRNGRandomGenerator()
#     rgen.setup(123, 5)

#     rgen.set_cursor(4950368079037995815)
    
def test_gen_keys():
    rgen = CSPRNGKeyGenerator()
    rgen.setup(123, 5)

    assert rgen._cursor == 0
    assert rgen.base_seed == 123
    assert rgen._modifier == 5

    five_keys = [k.hex() for k in rgen.get_keys(5)]
    assert len(five_keys) == 5
    assert five_keys == [
        'e112a6f022b874d9e0f8943c9f84d9671e68f28267812d5d3d965022e3dab27b', 
        '9ece5d07617c37fc284c7a27dafe9051c3a352a31c921d8a839a6940b2040da1',
        '1c6d0eab47476d937d9c8fb6adb56ae471d00c8e6230ed4c704304114e4994c6',
        '6d45bc1c6084910731cb7a4a2d0eb9c2f45f345f7978761fe89521e985a284d5',
        '8e5f89b733b2faa4e0c3ef706854c4e863d5612ae1e4a7f8c8d5436696952485'
    ]

    rgen.reset_seed()
    assert [k.hex() for k in rgen.get_keys(5)] == five_keys, "Did not generate the same keys"

    rgen.reset_seed(90)
    five_other_keys = [k.hex() for k in rgen.get_keys(5)]
    assert five_other_keys != five_keys, "Generate the same keys"

    all_keys = five_other_keys + five_keys
    assert len(all_keys) == len(set(all_keys)), "Same keys generated twice"