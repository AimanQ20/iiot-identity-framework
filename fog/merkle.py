"""Standard Merkle-tree implementation.

MEMBER 1:
- Deterministic leaf sorting
- Tree/root construction
- Inclusion-proof generation
- Inclusion-proof verification
"""

import hashlib


def hash_pair(left: bytes, right: bytes) -> bytes:
    """Hash two child nodes to create their parent."""

    return hashlib.sha256(left + right).digest()


def normalize_leaves(leaves: list[bytes]) -> list[bytes]:
    """Sort leaves deterministically and reject duplicates."""

    if not leaves:
        raise ValueError("Cannot build a Merkle tree without leaves")

    sorted_leaves = sorted(leaves)

    if len(sorted_leaves) != len(set(sorted_leaves)):
        raise ValueError("Duplicate Merkle leaves are not permitted")

    return sorted_leaves


def build_merkle_root(leaves: list[bytes]) -> bytes:
    """Build one Merkle root from the completed batch."""

    level = normalize_leaves(leaves)

    while len(level) > 1:
        # Duplicate the final node when the number of nodes is odd.
        if len(level) % 2 == 1:
            level.append(level[-1])

        next_level = []

        for index in range(0, len(level), 2):
            left = level[index]
            right = level[index + 1]
            next_level.append(hash_pair(left, right))

        level = next_level

    return level[0]


def generate_inclusion_proof(
    leaves: list[bytes],
    target_leaf: bytes,
) -> list[dict[str, str]]:
    """Generate the sibling path for one target leaf."""

    level = normalize_leaves(leaves)

    try:
        target_index = level.index(target_leaf)
    except ValueError as exc:
        raise ValueError("Target leaf is not present in the batch") from exc

    proof: list[dict[str, str]] = []

    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])

        # An even index is a left child.
        if target_index % 2 == 0:
            sibling_index = target_index + 1
            sibling_position = "right"
        else:
            sibling_index = target_index - 1
            sibling_position = "left"

        proof.append(
            {
                "hash": level[sibling_index].hex(),
                "position": sibling_position,
            }
        )

        next_level = []

        for index in range(0, len(level), 2):
            next_level.append(
                hash_pair(level[index], level[index + 1])
            )

        target_index //= 2
        level = next_level

    return proof


def verify_inclusion_proof(
    leaf: bytes,
    proof: list[dict[str, str]],
    trusted_root: bytes,
) -> bool:
    """Reconstruct the root from a leaf and its proof."""

    current_hash = leaf

    try:
        for sibling in proof:
            sibling_hash = bytes.fromhex(sibling["hash"])
            position = sibling["position"]

            if position == "left":
                current_hash = hash_pair(
                    sibling_hash,
                    current_hash,
                )
            elif position == "right":
                current_hash = hash_pair(
                    current_hash,
                    sibling_hash,
                )
            else:
                return False

    except (KeyError, TypeError, ValueError):
        return False

    return current_hash == trusted_root