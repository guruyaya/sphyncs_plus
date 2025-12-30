
from random import Random
from .generic import GenericKeyGenerator

class CSPRNGKeyGenerator(GenericKeyGenerator):
  _instance: Random
  protocol = "CSPRNG"
  _jump_modifier = 0
  max_jump = 2** 27
  _physical_jump = 0

  def __init__(self, instance: None|Random=None, max_jump=None):
    self._instance = instance or Random()
    self.max_jump = max_jump or self.max_jump

  def _set_seed(self, seed):
    self._instance.seed(seed)

  def _get_modified_seed(self):
    modeifier_effect = self._modifier * (2**self.key_size_bytes)
    return (self.base_seed + modeifier_effect + self._jump_modifier) % (8 ** self.key_size_bytes)
  
  def _jump(self, jump: int) -> None:
    if jump >= self.max_jump:
      self._jump_modifier = jump // self.max_jump
      jump = jump % self.max_jump
      self.reset_seed()

    relative_jump = jump - self._cursor
    
    if relative_jump < 0:
        self.reset_seed()
        relative_jump = jump
    self._physical_jump = jump # For testing purpose
    
    jump_size = jump * self.key_size_bytes
    self._instance.randbytes(jump_size)

  def _get_rand_key(self) -> bytes:
    self._physical_jump += 1
    return self._instance.randbytes(self.key_size_bytes)