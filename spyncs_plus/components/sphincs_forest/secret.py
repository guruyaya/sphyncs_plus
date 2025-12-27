from typing import Optional
from spyncs_plus.helpers.hashers import GenericHasher, SHA256Hasher
from spyncs_plus.helpers.random_generators import GenericRandomGenerator, CSPRNGRandomGenerator
from secrets import randbelow

class SphincsForestSecret():
    hasher: GenericHasher
    random_generator: GenericRandomGenerator
    _secret_key: int
    _max_key_num: int
    _inner_trees_last_level: int
    num_levels = 16
    num_inner_levels = 4
    
    class RandomKeyTooHigh(Exception):
        def __init__(self, key_num, max_key):
            super().__init__(f"Random key ({key_num}) must be lower than the allowed {max_key}")

    def __init__(self, hasher: GenericHasher, random_generator: GenericRandomGenerator, secret_key: int):
        self.hasher = hasher
        self._secret_key = secret_key
        self.random_generator = random_generator.setup(secret_key)
        self._inner_trees_last_level = 2**self.num_inner_levels
        self._max_key_num = self._inner_trees_last_level**self.num_levels

    def get_private_key(self, key_num:Optional[int]=None):
        key_num_int = key_num or randbelow(self._max_key_num)
        if key_num_int >= self._max_key_num:
            raise self.RandomKeyTooHigh(key_num_int, self._max_key_num)
        
        this_level_tree = key_num_int
        print (f"** Getting levels for key num {key_num_int}")
        for level in range (self.num_levels-1, -1, -1):
            this_level_branch = this_level_tree % self._inner_trees_last_level
            this_level_tree = this_level_tree // self._inner_trees_last_level
            
            print (f"level {level}, Tree {this_level_tree}, branch {this_level_branch}")
if __name__ == '__main__':
    # this is for local testing purpose
    secret = SphincsForestSecret(SHA256Hasher(), CSPRNGRandomGenerator(), 123)
    # assert secret._max_key_num > 2**64
    assert secret._max_key_num == 2**64
    secret.get_private_key(3)
    secret.get_private_key(6)
    secret.get_private_key(secret._max_key_num-1)
    secret.get_private_key(424967295)
