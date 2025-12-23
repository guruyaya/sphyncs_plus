
from spyncs_plus.helpers.hashers.sha256 import SHA256Hasher

def test_sha256_haser():
    hash = SHA256Hasher()
    assert hash(b"Hello Worl").hex() == '12fec4c65dd4455c48aff8977a7cd8ccb97539ad4cd7c37f13cf71ba8bee9a98'