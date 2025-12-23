
from random import Random
from .generic import GenericRandomGenerator

class CSPRNGRandomGenerator(GenericRandomGenerator):
  _instance: Random
  def __init__(self, instance: None|Random):
    random_instance = instance or Random()
    self._instance = random_instance

  def _set_seed(self, seed):
    self._instance.seed(seed)

  def _jump(self, jump: int) -> None:
    self._instance.randbytes(jump * self.key_size_bytes)

  def _get_rand_key(self) -> bytes:
    return self._instance.randbytes(self.key_size_bytes)