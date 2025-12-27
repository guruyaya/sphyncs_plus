from spyncs_plus.helpers.hashers.generic import GenericHasher
from .proof import SphincsTreeProof


class SphincsTreePublic:
  num_levels = 4
  public_key: bytes
  hasher: GenericHasher

  level_up_proof: None|SphincsTreeProof = None

  def __init__(self, hasher: GenericHasher, public_key: bytes, num_levels:None|int=None):
    self.hasher = hasher
    self.public_key = public_key
    self.num_levels = num_levels or self.num_levels
    if self.num_levels > 255:
      raise Exception("Only supports up to 255 levels in one tree")
    
  def is_level_up_signed(self):
    return isinstance(self.level_up_proof, SphincsTreeProof) and self.level_up_proof.verify()
