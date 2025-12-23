import hashlib
from .generic import GenericHasher

class SHA256Hasher(GenericHasher):
  protocol: str = "SHA256"
  
  def _hash(self, data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

