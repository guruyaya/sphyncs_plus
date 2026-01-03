from secrets import randbelow
from typing import Optional

from spyncs_plus.components.shpincs_tree.proof import SphincsTreeProof
from spyncs_plus.components.shpincs_tree.secret import SphincsTreeSecret
from spyncs_plus.helpers.hashers import GenericHasher
from spyncs_plus.helpers.key_generators import GenericKeyGenerator
from .public import SphincsForestPublicKey, SphincsForestProof

class SphincsForestSecretKey():
    levels: list[SphincsTreeSecret]
    key_num: int
    hasher: GenericHasher

    _last_level_size: int
    
    def __init__(self, levels: list[SphincsTreeSecret], key_num: int, hasher: GenericHasher):
        self.levels = levels
        self.key_num = key_num
        self.hasher = hasher
        
        self._last_level_size = len(levels[0].levels[0]) * 2

    def sign(self, message: bytes) -> SphincsForestProof:
        message_hash = self.hasher(message)
        levels:list[SphincsTreeProof|None] = [level.level_up_proof for level in self.levels]
        message_signature = self.levels[0].sign(message, key_num=self.key_num % self._last_level_size)
        return SphincsForestProof(hash=message_hash, levels=levels, signature=message_signature)

class SphincsForestSecret(SphincsForestPublicKey):
    key_generator: GenericKeyGenerator
    _keys_to_generate_per_tree:int
    _secret_key: int
    _max_key_num: int
    _inner_trees_last_level: int
    # TODO - computing the top tree on every key generation is wasteful, and should be caches on init, 
    # when public key hash is computed
    
    class RandomKeyTooHigh(Exception):
        def __init__(self, key_num, max_key):
            super().__init__(f"Random key ({key_num}) must be lower than the allowed {max_key}")

    def __init__(self, hasher: GenericHasher, key_generator: GenericKeyGenerator, secret_key: int, 
                 num_levels: int|None=None, trees_num_levels: int|None=None):
        self.hasher = hasher
        self._secret_key = secret_key
        self.num_levels = num_levels or self.num_levels
        self.trees_per_level = trees_num_levels or self.trees_per_level
        
        self.key_generator = key_generator.setup(secret_key)
        self._inner_trees_last_level = 2**self.trees_per_level
        self._max_key_num = self._inner_trees_last_level**self.num_levels
        self._keys_to_generate_per_tree = (hasher.key_size_bytes + hasher._checksum_size) * self._inner_trees_last_level

        to_sphincs_tree_secret, _, _ = self.compute_level(0, 0)
        
        self.pk_hash = to_sphincs_tree_secret.public_key

        
    def compute_level(self, level_num, this_level_tree) -> tuple[SphincsTreeSecret, int, int]:
        this_level_branch = this_level_tree % self._inner_trees_last_level
        this_level_tree = this_level_tree // self._inner_trees_last_level

        # build tree, by number
        self.key_generator.reset_seed(level_num)
        self.key_generator.set_cursor(self._keys_to_generate_per_tree * this_level_tree)

        level = SphincsTreeSecret(self.hasher, self.key_generator, self.trees_per_level)

        return level, this_level_branch, this_level_tree

    def get_secret_key(self, key_num:Optional[int]=None) -> SphincsForestSecretKey:
        key_num_int = key_num if isinstance(key_num, int) else randbelow(self._max_key_num)
        if key_num_int >= self._max_key_num:
            raise self.RandomKeyTooHigh(key_num_int, self._max_key_num)
        
        this_level_tree = key_num_int

        all_trees:list[SphincsTreeSecret] = []

        for level_num in range (self.num_levels-1, -1, -1):
            level, this_level_branch, this_level_tree = self.compute_level(level_num, this_level_tree)
            
            if len(all_trees) > 0:
                level.sign_level_down(all_trees[-1], this_level_branch)
            all_trees += [level]
        
        print (f"{key_num_int=}")
        return SphincsForestSecretKey(key_num=key_num_int, levels=all_trees, hasher=self.hasher)
