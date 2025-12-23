from abc import ABC, abstractmethod

class GenericHasher(ABC):
  repeat_count = 255
  key_size_bytes = 32
  protocol: str = "Generic"
  version: str = "1.0a"

  class TooManyHashesException(Exception):
    times: int
    repeat_count: int
    def __init__(self, repeat_count: int, times: int) -> None:
      self.repeat_count = repeat_count
      self.times = times
      return super().__init__(f"You've requested to repeat {times}, but you can only go up to {repeat_count}")
    pass

  def __init__(self, repeat_count:int|None=None):
    if repeat_count:
      self.repeat_count = repeat_count

  @abstractmethod
  def _hash(self, data: bytes) -> bytes:
    pass

  def __call__(self, data: bytes) -> bytes:
    return self._hash(data)

  def test(self, data: bytes, hash: bytes) -> bool:
    return self._hash(data) == hash

  def concatenate_hash(self, data_list: list[bytes]) -> bytes:
    result = b""
    for data in data_list:
      result += data
    return self._hash(result)

  def forward(self, data:bytes, times:int|bytes, reverse=False) -> bytes:
    times_int = times if isinstance(times, int) else int.from_bytes(times)
    if times_int > self.repeat_count:
      raise GenericHasher.TooManyHashesException(self.repeat_count, times_int)
    answer = data
    if reverse:
      times_int = self.repeat_count - times_int

    for _ in range(times_int):
      answer = self._hash(answer)

    return answer

