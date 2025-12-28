
from random import Random
from .generic import GenericRandomGenerator

class CSPRNGRandomGenerator(GenericRandomGenerator):
  _instance: Random
  protocol = "CSPRNG"
  
  def __init__(self, instance: None|Random=None):
    self._instance = instance or Random()

  def _set_seed(self, seed):
    self._instance.seed(seed)

  def _jump(self, jump: int) -> None:
    jump_size = jump * self.key_size_bytes
    max_jump = 2**27

    for jmp in range(jump_size // max_jump):
      self._instance.randbytes(max_jump)
    self._instance.randbytes(jump_size % max_jump)

  def _get_rand_key(self) -> bytes:
    return self._instance.randbytes(self.key_size_bytes)