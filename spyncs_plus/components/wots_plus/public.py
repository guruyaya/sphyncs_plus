from typing import Optional
from spyncs_plus.helpers.hashers import GenericHasher

class WotsPlusPublic:
  hasher: GenericHasher
  public_key: bytes = b''
  version = "1.0a"

  def __init__(self, hasher: GenericHasher, p_key: Optional[bytes]=None):
    self.hasher = hasher
    self.public_key = p_key or b''

  @staticmethod
  def hash_to_single_bytes(hash: bytes) -> list[bytes]:
    return [hash[i:i+1] for i in range(0, len(hash), 1)]

  def calculate_public_key_from_message(self, message: bytes, signature: list[bytes], pre_hashed=False) -> bytes:
    message_hash = message if pre_hashed else self.hasher(message)
    message_bytes = self.hash_to_single_bytes(message_hash)

    values = []
    forward_sum = 0
    for key, message_byte in zip(signature, message_bytes):
      forward_sum += self.hasher.repeat_count - int.from_bytes(message_byte)
      values.append(self.hasher.forward(data=key, times=message_byte, reverse=True))

    forward_checksum = self.hash_to_single_bytes(int.to_bytes(forward_sum, 2))

    values.append(self.hasher.forward(signature[self.hasher.key_size_bytes], forward_checksum[0], reverse=True))
    values.append(self.hasher.forward(signature[self.hasher.key_size_bytes + 1], forward_checksum[1], reverse=True))
    return self.hasher.concatenate_hash(values)

  def verify(self, message: bytes, signature: list[bytes]) -> bool:
    if (self.public_key == b''):
      raise Exception("Public key is not set")

    return self.public_key == self.calculate_public_key_from_message(message, signature)

