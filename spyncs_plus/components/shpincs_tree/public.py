from spyncs_plus.helpers.hashers.generic import GenericHasher
from .proof import SphincsTreeProof


class SphincsTreePublic:
  num_levels = 2
  public_key: bytes
  hasher: GenericHasher

  level_up_proof: None|SphincsTreeProof = None

  def __init__(self, hasher: GenericHasher, public_key: bytes):
    self.hasher = hasher
    self.public_key = public_key

  def is_level_up_signed(self):
    return isinstance(self.level_up_proof, SphincsTreeProof) and self.level_up_proof.verify()
