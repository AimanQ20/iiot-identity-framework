import hashlib

from fog.merkle import (
    build_merkle_root,
    generate_inclusion_proof,
    verify_inclusion_proof,
)


def make_leaf(value: str) -> bytes:
    return hashlib.sha256(
        value.encode("utf-8")
    ).digest()


def test_every_generated_proof_verifies():
    leaves = [
        make_leaf("device-1"),
        make_leaf("device-2"),
        make_leaf("device-3"),
        make_leaf("device-4"),
        make_leaf("device-5"),
    ]

    root = build_merkle_root(leaves)

    for leaf in leaves:
        proof = generate_inclusion_proof(
            leaves,
            leaf,
        )

        assert verify_inclusion_proof(
            leaf,
            proof,
            root,
        )


def test_tampered_proof_fails():
    leaves = [
        make_leaf("device-1"),
        make_leaf("device-2"),
        make_leaf("device-3"),
    ]

    target = leaves[0]
    root = build_merkle_root(leaves)

    proof = generate_inclusion_proof(
        leaves,
        target,
    )

    # Replace one valid sibling with a false hash.
    proof[0]["hash"] = "00" * 32

    assert not verify_inclusion_proof(
        target,
        proof,
        root,
    )


def test_root_is_independent_of_arrival_order():
    leaves = [
        make_leaf("device-a"),
        make_leaf("device-b"),
        make_leaf("device-c"),
    ]

    first_root = build_merkle_root(leaves)
    second_root = build_merkle_root(
        list(reversed(leaves))
    )

    assert first_root == second_root


def test_odd_number_of_leaves_is_supported():
    leaves = [
        make_leaf("device-a"),
        make_leaf("device-b"),
        make_leaf("device-c"),
    ]

    root = build_merkle_root(leaves)

    for leaf in leaves:
        proof = generate_inclusion_proof(
            leaves,
            leaf,
        )

        assert verify_inclusion_proof(
            leaf,
            proof,
            root,
        )