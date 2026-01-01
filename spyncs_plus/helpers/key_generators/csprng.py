
from random import Random
from .generic import GenericKeyGenerator

class CSPRNGKeyGenerator(GenericKeyGenerator):
  _instance: Random
  protocol = "CSPRNG"

  def __init__(self, instance: None|Random=None, max_jump=None):
    self._instance = instance or Random()

  def _set_seed(self, seed):
    self._instance.seed(seed)

  def _get_modified_seed(self):
    modeifier_effect = self._modifier * (2**self.key_size_bytes)
    return (self.base_seed + modeifier_effect + self._cursor) % (8 ** self.key_size_bytes)
  
  def _set_reset_cursor(self):
      self._cursor = 0

  def _jump(self, jump: int) -> None:
    # We reset the seed before getting every key, to the cursor
    pass

  def _get_rand_key(self) -> bytes:
    self._set_seed(self._get_modified_seed())
    return self._instance.randbytes(self.key_size_bytes)
