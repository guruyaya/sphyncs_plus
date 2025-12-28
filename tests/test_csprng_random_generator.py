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
        '8b3f4433467d1df398023e4f0077a2b73485e2f7656d9f4baff063caeebc4edf', 
        '82af84ab2c56cf017e71791b95bc85893ae19bfb2b34a524c1c40524d8ebba8e',
        '765ca662c0f5e20dd543a86569c6892a3edee542aa16e30e37d8884767f11025',
        '387bb4eb48b5ed1d685da1f57be7b1202fdb5fbc962f6bdcaaa528bd30ceaf8f',
        '2edc7a50169015c511fcddc20b2f19b0028d2f4e3ac5fca8bac88ac3b8be176c'
    ]

    rgen.reset_seed()
    assert [k.hex() for k in rgen.get_keys(5)] == five_keys, "Did not generate the same keys"

    rgen.reset_seed(1)
    five_other_keys = [k.hex() for k in rgen.get_keys(5)]
    for i, key in enumerate(five_other_keys):
        assert key not in five_keys, f"Key number {i} in other keys, reperats here {five_keys}"

    assert five_other_keys != five_keys, "Generate the same keys"

    all_keys = five_other_keys + five_keys
    assert len(all_keys) == len(set(all_keys)), "Same keys generated twice"