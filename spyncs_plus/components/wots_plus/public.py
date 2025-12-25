from typing import Optional
from spyncs_plus.helpers.hashers import GenericHasher

class WotsPlusPublic:
  hasher: GenericHasher
  p_key: Optional[bytes]
  version = "1.0a"

  def __init__(self, hasher: GenericHasher, p_key: Optional[bytes]=None):
    self.hasher = hasher
    self.p_key = p_key

  @staticmethod
  def hash_to_single_bytes(hash: bytes) -> list[bytes]:
    return [hash[i:i+1] for i in range(0, len(hash), 1)]

  def get_p_key(self, message: bytes, signature: list[bytes], pre_hashed=False) -> bytes:
    message_hash = message if pre_hashed else self.hasher(message)
    message_bytes = self.hash_to_single_bytes(message_hash)

    values = []
    forward_sum = 0
    for key, message_byte in zip(signature, message_bytes):
      forward_sum += self.hasher.repeat_count - int.from_bytes(message_byte)
      values.append(self.hasher.forward(data=key, times=message_byte, reverse=True))

    forward_checksum = self.hash_to_single_bytes(int.to_bytes(forward_sum, 2))

    values.append(self.hasher.forward(signature[32], forward_checksum[0], reverse=True))
    values.append(self.hasher.forward(signature[33], forward_checksum[1], reverse=True))
    return self.hasher.concatenate_hash(values)

  def verify(self, message: bytes, signature: list[bytes]) -> bool:
    if (self.p_key is None):
      raise Exception("Public key is not set")

    return self.p_key == self.get_p_key(message, signature)

