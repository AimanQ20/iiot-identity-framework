"""MEMBER 1: standard Merkle tree construction and proof verification."""

import hashlib


def hash_pair(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(left + right).digest()


def build_merkle_root(leaves: list[bytes]) -> bytes:
    """Working shared helper: sort leaves and duplicate the final odd node."""
    if not leaves:
        raise ValueError("Cannot build a Merkle tree without leaves")
    level = sorted(leaves)
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        level = [hash_pair(level[i], level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


def generate_inclusion_proof(leaves: list[bytes], target_leaf: bytes) -> list[dict[str, str]]:
    """TODO MEMBER 1: return sibling hashes and their left/right positions."""
    raise NotImplementedError


def verify_inclusion_proof(leaf: bytes, proof: list[dict[str, str]], trusted_root: bytes) -> bool:
    """TODO MEMBER 1: reconstruct and compare the epoch root."""
    raise NotImplementedError

