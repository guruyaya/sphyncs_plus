
from spyncs_plus.helpers.hashers.sha256 import SHA256Hasher

def test_sha256_haser():
    hasher = SHA256Hasher()
    assert hasher.repeat_count == 255
    assert hasher.key_size_bytes == 32
    assert hasher.protocol == 'SHA256'
    assert hasher.version == "1.0a"

    assert hasher(b"Hello Worl").hex() == '12fec4c65dd4455c48aff8977a7cd8ccb97539ad4cd7c37f13cf71ba8bee9a98'
    
    target_hash = hasher.forward(b'Goodbye world', hasher.repeat_count)
    assert target_hash.hex()  == 'e676c2813946e471939c74ddf19703cd4bd39ccf1a0ae7973ae6543f7ba3c834'

    midway_hash = hasher.forward(b'Goodbye world', 17)
    assert midway_hash.hex() ==  '0744e60475d014125bd5676d3611c338b449141f90cf6b2004a800e95260883e'

    all_the_way_hash = hasher.forward(midway_hash, 17, reverse=True)
    assert target_hash == all_the_way_hash

