
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
    levels = list[SphincsTreeProof|None]
    signature: SphincsTreeProof
    public_key: bytes
    hasher: GenericHasher

    def __init__(self, levels, signature, public_key, hasher):
        self.levels = levels
        self.signature = signature
        self.public_key = public_key
        self.hasher = hasher

    def __repr__(self):
        return f"<SphincsForestProof hash={self.hash.hex()} levels={self.levels} signature={self.signature} />"
    
    def verify(self, message, ignore_wrong_hash=False, allready_hashed=False):
        message_hash = message if allready_hashed else self.hasher(message)
        if not ignore_wrong_hash:
            if self.signature.message_hash != message_hash:
                return False
        
        all_levels_signed_except_root = all(level.verify() for level in self.levels[:-1])
        is_public_key_valid = self.levels[-2].public_key == self.public_key
        signature_match = self.signature.verify(hasher=self.hasher, message_hash=message_hash)
        return all([all_levels_signed_except_root, is_public_key_valid, signature_match]) 