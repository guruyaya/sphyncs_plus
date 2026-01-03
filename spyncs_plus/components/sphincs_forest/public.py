
from spyncs_plus.components.shpincs_tree.proof import SphincsTreeProof
from spyncs_plus.helpers.hashers.generic import GenericHasher

class SphincsForestPublicKey():
    pk_hash: bytes
    hasher: GenericHasher
    num_levels = 32
    trees_per_level = 2

    def __init__(self, public_key:bytes, hasher: GenericHasher, num_levels: int|None=None, trees_per_level: int|None=None):
        self.pk_hash = public_key
        self.hasher = hasher
        self.num_levels = num_levels or self.num_levels
        self.trees_per_level = trees_per_level or self.trees_per_level
    
class SphincsForestProof():
    hash: bytes
    levels = list[SphincsTreeProof|None]
    signature: SphincsTreeProof

    def __init__(self, hash, levels, signature):
        self.hash = hash
        self.levels = levels
        self.signature = signature
