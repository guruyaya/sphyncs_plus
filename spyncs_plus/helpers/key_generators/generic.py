from abc import ABC, abstractmethod
from collections.abc import Iterable
from typing import Self

class GenericKeyGenerator(ABC):
    base_seed: int
    key_size_bytes = 32
    protocol = "GENERIC"
    version = "1.0a"
    _cursor: int = 0
    _modifier: int = 0


    class DidNotRunSetup(Exception):
        def __init__(self):
            super().__init__("Setup for random generator was not instanciated with a seed")

    @abstractmethod
    def _set_seed(self, seed):
        pass
    
    @abstractmethod
    def _get_rand_key(self) -> bytes:
        pass

    @abstractmethod
    def _jump(self, jump: int):
        pass
    
    @abstractmethod
    def _get_modified_seed(self):
        pass

    def setup(self, seed: int, modeifier:None|int=None) -> Self:
        self.base_seed = seed
        self.reset_seed(modeifier)
        return self # using the builder pattern for easier usage

    def _set_reset_cursor(self):
        self._cursor = 0

    def reset_seed(self, modifier:None|int=None):
        if not hasattr(self, "base_seed"):
            raise self.DidNotRunSetup()
        
        modifier_int = modifier or self._modifier
        
        if modifier is not None: # A modifier was set
            self._modifier = modifier_int
        
        self._set_seed(self._get_modified_seed())
        self._set_reset_cursor()

    def set_cursor(self, jump:int):
        if not hasattr(self, "base_seed"):
            raise self.DidNotRunSetup()

        self._jump(jump)
        self._cursor = jump

    def get_keys(self, number_of_keys=1) -> Iterable[bytes]:
        if not hasattr(self, "base_seed"):
            raise self.DidNotRunSetup()

        for _ in range(number_of_keys):
            yield self._get_rand_key()
            self._cursor += 1
