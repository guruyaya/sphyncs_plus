
from random import Random
from .generic import GenericKeyGenerator

class CSPRNGKeyGenerator(GenericKeyGenerator):
  _instance: Random
  protocol = "CSPRNG"
  
  def __init__(self, instance: None|Random=None):
    self._instance = instance or Random()

  def _set_seed(self, seed):
    self._instance.seed(seed)

  def _jump(self, jump: int) -> None:
    relative_jump = jump - self._cursor
    if relative_jump < 0:
        self.reset_seed()
        relative_jump = jump

    jump_size = jump * self.key_size_bytes
    self._instance.randbytes(jump_size)
    
  def _get_rand_key(self) -> bytes:
    return self._instance.randbytes(self.key_size_bytes)