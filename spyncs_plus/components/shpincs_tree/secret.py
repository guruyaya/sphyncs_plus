from spyncs_plus.helpers.hashers import GenericHasher
from spyncs_plus.helpers.key_generators import GenericKeyGenerator
from spyncs_plus.components.wots_plus import WotsPlusSecret
from .proof import SphincsTreeProof
from .public import SphincsTreePublic

class SphincsTreeSecret(SphincsTreePublic):
  base_level: list[list[WotsPlusSecret]]
  levels: list[list[list[bytes]]]

  @staticmethod
  def create_pairs(lst: list):
    return [[lst[i], lst[i+1]] for i in range(0, len(lst), 2)]

  def __init__(self, hasher: GenericHasher, key_generator: GenericKeyGenerator, num_levels:None|int=None):
    self.hasher = hasher
    self.num_levels = num_levels or self.num_levels
    if self.num_levels > 255:
      raise Exception("Does not support higher than 255 levels in one tree")

    self.base_level = self.create_pairs([WotsPlusSecret(hasher, key_generator) for _ in range(2 ** (self.num_levels))])
    self.levels = [[[w.public_key for w in l] for l in self.base_level]]

    for i in range(self.num_levels - 1):
      prev_level = self.levels[i]

      this_level = [hasher.concatenate_hash(pair) for pair in prev_level]

      self.levels.append(self.create_pairs(this_level))

    self.public_key = hasher.concatenate_hash(self.levels[-1][0])

  def sign(self, message: bytes, key_num: int, allready_hashed=False) -> SphincsTreeProof:
    if key_num >= 2 ** self.num_levels:
      raise Exception(f"Key number {key_num} is out of range (must be lower than ({2 ** self.num_levels}))")

    pair_num_pos = []

    wots_key = self.base_level[key_num // 2][key_num % 2]
    signature = wots_key.sign(message, allready_hashed=allready_hashed)

    for i in range(self.num_levels):
      pair_num = key_num // 2
      pair_pos = key_num % 2

      pair_num_pos.append((pair_pos, self.levels[i][pair_num][1-pair_pos]))
      key_num = pair_num

    message_hash = self.hasher(message)
    return SphincsTreeProof(message_hash=message_hash, signature=signature, proof_tree=pair_num_pos, 
                            public_key=self.public_key)

  def sign_level_down(self, level_down: SphincsTreePublic, key_num: int):
    level_down.level_up_proof = self.sign(level_down.public_key, key_num)
    return level_down

