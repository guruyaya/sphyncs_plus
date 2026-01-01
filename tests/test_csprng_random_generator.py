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

def test_modifier_works():
    rgen = CSPRNGKeyGenerator()
    rgen.setup(123, 5)

    five_keys = [k.hex() for k in rgen.get_keys(5)]

    rgen.reset_seed(6)
    five_other_keys = [k.hex() for k in rgen.get_keys(5)]

    assert all(k not in five_other_keys for k in five_keys)


def test_high_keygen():
    rgen = CSPRNGKeyGenerator()
    rgen.setup(123, 4950368079037995816)

    five_keys = [k.hex() for k in rgen.get_keys(5)]

    rgen.reset_seed(4950368079037995815)
    five_other_keys = [k.hex() for k in rgen.get_keys(5)]

    assert all(k not in five_other_keys for k in five_keys)
    
def test_gen_keys():
    rgen = CSPRNGKeyGenerator()
    rgen.setup(123, 5)

    assert rgen._cursor == 0
    assert rgen.base_seed == 123
    assert rgen._modifier == 5

    five_keys = [k.hex() for k in rgen.get_keys(5)]
    assert len(five_keys) == 5

    rgen.set_cursor(1)
    assert [k.hex() for k in rgen.get_keys(4)] == five_keys[1:], "Did not generate the same keys"

    rgen.reset_seed(1)
    five_other_keys = [k.hex() for k in rgen.get_keys(5)]
    for i, key in enumerate(five_other_keys):
        assert key not in five_keys, f"Key number {i} in other keys, reperats here {five_keys}"

    assert five_other_keys != five_keys, "Generate the same keys"

    all_keys = five_other_keys + five_keys
    assert len(all_keys) == len(set(all_keys)), "Same keys generated twice"

def test_big_mid_max_jump_handling():
    rgen = CSPRNGKeyGenerator(max_jump=1024)
    rgen.setup(123, 0)

    rgen.set_cursor(1023)
    five_keys = [k.hex()[:6] for k in rgen.get_keys(5)]
    assert rgen._cursor == 1028

    rgen.set_cursor(1025)
    three_keys = [k.hex()[:6] for k in rgen.get_keys(3)]
    assert rgen._cursor == 1028

    assert five_keys[2:] == three_keys


def test_big_jumps():
    rgen = CSPRNGKeyGenerator(max_jump=1024)
    rgen.setup(123, 0)

    rgen.set_cursor(1)
    five_keys = [k.hex()[:6] for k in rgen.get_keys(5)]
    assert rgen._cursor == 6
    assert len(set(five_keys)) == 5, f"Found repeating keys: {five_keys}"
    
    rgen.set_cursor(1025)
    assert rgen._cursor == 1025

    five_other_keys = [k.hex()[:6] for k in rgen.get_keys(5)]
    assert len(set(five_other_keys)) == 5, "Found repeating keys"

    assert all(k not in five_other_keys for k in five_keys)
    five_keys += five_other_keys
    assert len(set(five_keys)) == 10, five_keys # No repeating keys
    assert rgen._cursor == 1030

    rgen.set_cursor(2049)
    assert rgen._cursor == 2049

    five_other_keys = [k.hex() for k in rgen.get_keys(5)]

    assert all(k not in five_other_keys for k in five_keys)

