
import math
from .public import WotsPlusPublic
from spyncs_plus.helpers.random_generators import GenericRandomGenerator
from spyncs_plus.helpers.hashers import GenericHasher

BYTE_SIZE = 8

class WotsPlusSecret(WotsPlusPublic):
  randomGen: GenericRandomGenerator
  secret_key_size = 32

  s_keys: list[bytes]
  checksum_keys: list[bytes]

  _required_checksum_key_count: int

  def __init__(self, hasher: GenericHasher, randomGen: GenericRandomGenerator):
    self.hasher = hasher
    self.randomGen = randomGen

    self._required_checksum_key_count = hasher._checksum_size
    
    # Hasing the initial keys prevent direct access to the results of the random generator
    self.s_keys = [self.hasher(key) for key in self.randomGen.get_keys(self.hasher.key_size_bytes)]
    self.checksum_keys = [self.hasher(key) for key in self.randomGen.get_keys(self._required_checksum_key_count)]

    p_keys = [self.hasher.forward(h, self.hasher.repeat_count) for h in (self.s_keys + self.checksum_keys)]
    self.public_key = self.hasher.concatenate_hash(p_keys)

  def sign(self, message: bytes) -> list[bytes]:
    message_hash = self.hasher(message)
    message_bytes = self.hash_to_single_bytes(message_hash)

    values = []
    forward_sum = 0
    for key, message_byte in zip(self.s_keys, message_bytes):
      forward_sum += self.hasher.repeat_count - int.from_bytes(message_byte)
      values.append(self.hasher.forward(key, message_byte))

    forward_checksum = self.hash_to_single_bytes(int.to_bytes(forward_sum, 2))
    values.append(self.hasher.forward(self.checksum_keys[0], forward_checksum[0]))
    values.append(self.hasher.forward(self.checksum_keys[1], forward_checksum[1]))
    return values

  def get_public_wots(self) -> WotsPlusPublic:
    return WotsPlusPublic(self.hasher, self.public_key)
