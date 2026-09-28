"""MEMBER 1: standard Merkle tree construction and proof verification.

generate_inclusion_proof / verify_inclusion_proof were left as TODOs in the
skeleton but are required to exercise Phase 3 permanent verification, so
they're filled in here using the exact same sort-and-duplicate-odd-node rule
as build_merkle_root. Ownership stays with Member 1 (Phase 1 batch build) --
Phase 3's own scope (device/token binding, nonce/timestamp, RBAC, ALLOW/DENY)
lives in fog/access_service.py.
"""

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
    """Sibling path for target_leaf against the same sorted, odd-duplicated tree
    build_merkle_root builds. Each entry's "position" says where the sibling
    sits relative to the running node: "right" means hash(node, sibling),
    "left" means hash(sibling, node)."""
    if target_leaf not in leaves:
        raise ValueError("Leaf is not part of the given leaf set")

    level = sorted(leaves)
    index = level.index(target_leaf)
    proof: list[dict[str, str]] = []

    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        if index % 2 == 0:
            sibling_index, position = index + 1, "right"
        else:
            sibling_index, position = index - 1, "left"
        proof.append({"hash": level[sibling_index].hex(), "position": position})
        level = [hash_pair(level[i], level[i + 1]) for i in range(0, len(level), 2)]
        index //= 2

    return proof


def verify_inclusion_proof(leaf: bytes, proof: list[dict[str, str]], trusted_root: bytes) -> bool:
    """Reconstruct the root by walking the sibling path and compare to trusted_root."""
    node = leaf
    for step in proof:
        try:
            sibling = bytes.fromhex(step["hash"])
        except (KeyError, ValueError):
            return False
        if step.get("position") == "right":
            node = hash_pair(node, sibling)
        elif step.get("position") == "left":
            node = hash_pair(sibling, node)
        else:
            return False
    return node == trusted_root
