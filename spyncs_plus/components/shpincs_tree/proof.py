from dataclasses import dataclass
from typing import Optional, Self
from spyncs_plus.helpers.hashers import SHA256Hasher, GenericHasher
from spyncs_plus.components.wots_plus import WotsPlusPublic

class ProofHashTypes:
  SHA256="SHA256"

  @classmethod
  def get_hasher(cls, type: str):
    HASH_TO_TYPE = {cls.SHA256: SHA256Hasher}
    return HASH_TO_TYPE[type]

@dataclass
class SphincsTreeProof:
  version = "1.0a"
  message_hash: bytes
  signature: list[bytes]
  proof_tree: list[ tuple[int, bytes] ] # (pair_pos, other chain hash)
  public_key: Optional[bytes] = None
  hash_type:str = ProofHashTypes.SHA256
  hash_type_version: str = "1.0a"

  class NoSuchHushType(Exception):
    def __init__(self, hash_type):
      super().__init__(f"Installed version of SphincsTree does not support '{hash_type}' hashers. only supports the following hash types: {ProofHashTypes.SHA256}")

  def get_result(self, hasher:Optional[GenericHasher]=None, message_hash:bytes|None=None):
    to_check = message_hash or self.message_hash
    my_hasher = hasher or ProofHashTypes.get_hasher(self.hash_type)()
    wots = WotsPlusPublic(my_hasher)
    this_hash = wots.calculate_public_key_from_message(to_check, self.signature, pre_hashed=True)
    for position, other_hash in self.proof_tree:
      to_concat = [other_hash, this_hash] if position == 1 else [this_hash, other_hash]
      this_hash = (my_hasher.concatenate_hash(to_concat))
    return this_hash

  def verify(self, hasher:Optional[GenericHasher]=None, message_hash:bytes|None=None) -> bool:
    if self.public_key == None:
      raise Exception("Public key is not set")
    return self.public_key == self.get_result(hasher, message_hash)

  def to_bytes(self) -> bytes:
    if self.hash_type == ProofHashTypes.SHA256:
        proof_size = len(self.proof_tree)
        proofs_bytes = b''.join(int.to_bytes(tree[0], 8) + tree[1] for tree in self.proof_tree)

        return ( self.hash_type.encode() + "|".encode() + self.hash_type_version.encode() + "|".encode() +
            self.message_hash + b''.join(self.signature) +
                proof_size.to_bytes(1) +
                proofs_bytes + (self.public_key or int.to_bytes(0, 32)))
    else:
        raise self.NoSuchHushType(self.hash_type)

  @classmethod
  def from_bytes(cls, proof_bytes: bytes) -> Self:
    def bytes_pop(bts: bytes, n: int) -> tuple[bytes, bytes]:
      return bts[:n], bts[n:]
    
    hash_type, hash_type_version, proof = proof_bytes.split(b"|", 2)
    message_hush, proof = bytes_pop(proof, 32)

    if hash_type.decode() == ProofHashTypes.SHA256:
        signature = []
        for _ in range(34):
            sig_part, proof = bytes_pop(proof, 32)
            signature.append(sig_part)
        
        proof_tree = []

        num_levels, proof = bytes_pop(proof, 1)
        
        for _ in range(int.from_bytes(num_levels)):
            pair_pos, proof = bytes_pop(proof, 8)
            other_hash, proof = bytes_pop(proof, 32)
            proof_tree.append((int.from_bytes(pair_pos, 'big'), other_hash))
        public_key, proof = bytes_pop(proof, 32)

        return cls(message_hush, signature, proof_tree, public_key, hash_type.decode(), hash_type_version.decode())

    else:
      raise cls.NoSuchHushType(message_hush)

  def __repr__(self):
     return f"<SphincsTreeProof message_hash={self.message_hash.hex()} proof_size={len(self.proof_tree)} />"