from time import time
from typing import Optional
from spyncs_plus.components.shpincs_tree.secret import SphincsTreeSecret
from spyncs_plus.helpers.hashers import GenericHasher, SHA256Hasher
from spyncs_plus.helpers.key_generators import GenericKeyGenerator, CSPRNGKeyGenerator
from secrets import randbelow

class SphincsForestSecret():
    hasher: GenericHasher
    key_generator: GenericKeyGenerator
    num_levels = 16
    num_inner_levels = 4
    _keys_to_generate_per_tree:int
    _secret_key: int
    _max_key_num: int
    _inner_trees_last_level: int
    
    class RandomKeyTooHigh(Exception):
        def __init__(self, key_num, max_key):
            super().__init__(f"Random key ({key_num}) must be lower than the allowed {max_key}")

    def __init__(self, hasher: GenericHasher, key_generator: GenericKeyGenerator, secret_key: int):
        self.hasher = hasher
        self._secret_key = secret_key
        self.key_generator = key_generator.setup(secret_key)
        self._inner_trees_last_level = 2**self.num_inner_levels
        self._max_key_num = self._inner_trees_last_level**self.num_levels
        self._keys_to_generate_per_tree = (hasher.key_size_bytes + hasher._checksum_size) * self._inner_trees_last_level

    def get_private_key(self, key_num:Optional[int]=None) -> list[SphincsTreeSecret]:
        key_num_int = key_num or randbelow(self._max_key_num)
        if key_num_int >= self._max_key_num:
            raise self.RandomKeyTooHigh(key_num_int, self._max_key_num)
        
        this_level_tree = key_num_int

        print (f"Generaing key {key_num_int}")
        all_trees:list[SphincsTreeSecret] = []

        for level_num in range (self.num_levels-1, -1, -1):
            this_level_branch = this_level_tree % self._inner_trees_last_level
            this_level_tree = this_level_tree // self._inner_trees_last_level
            
            # build tree, by number
            self.key_generator.reset_seed(level_num)
            self.key_generator.set_cursor(self._keys_to_generate_per_tree * this_level_tree)
            
            level = SphincsTreeSecret(self.hasher, self.key_generator, self.num_inner_levels)
            if len(all_trees) > 0:
                level.sign_level_down(all_trees[-1], this_level_branch)
            all_trees += [level]
        return all_trees
