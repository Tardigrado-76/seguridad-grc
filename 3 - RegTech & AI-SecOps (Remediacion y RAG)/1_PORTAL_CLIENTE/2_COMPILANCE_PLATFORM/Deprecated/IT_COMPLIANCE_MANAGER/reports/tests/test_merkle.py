#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for the SHA-256 Merkle Tree construction engine."""

import hashlib
from pathlib import Path

from src.sealer.merkle import MerkleTreeBuilder


def _write_files(tmp_path: Path, names_and_content: dict):
    paths = []
    for name, content in names_and_content.items():
        p = tmp_path / name
        p.write_text(content, encoding="utf-8")
        paths.append(p)
    return paths


def test_merkle_root_is_deterministic(tmp_path):
    files = _write_files(tmp_path, {
        "a.md": "alpha",
        "b.md": "bravo",
        "c.md": "charlie",
    })
    root1, leaves1, _ = MerkleTreeBuilder(files).build_tree()
    root2, leaves2, _ = MerkleTreeBuilder(files).build_tree()

    assert root1 == root2
    assert len(root1) == 64  # SHA-256 hex
    assert leaves1 == leaves2
    assert set(leaves1.keys()) == {"a.md", "b.md", "c.md"}


def test_leaf_hashes_match_content(tmp_path):
    files = _write_files(tmp_path, {"doc.txt": "contenido evidencia"})
    _, leaves, _ = MerkleTreeBuilder(files).build_tree()

    expected = hashlib.sha256(b"contenido evidencia").hexdigest()
    assert leaves["doc.txt"] == expected


def test_single_file_root_is_leaf_hash(tmp_path):
    files = _write_files(tmp_path, {"solo.md": "unico"})
    root, leaves, _ = MerkleTreeBuilder(files).build_tree()

    assert root == leaves["solo.md"]


def test_empty_input_returns_empty_hash(tmp_path):
    root, leaves, _ = MerkleTreeBuilder([]).build_tree()

    assert leaves == {}
    assert root == hashlib.sha256(b"empty").hexdigest()


def test_ordering_independent(tmp_path):
    files = _write_files(tmp_path, {"x.txt": "uno", "y.txt": "dos"})
    root_a, _, _ = MerkleTreeBuilder(files).build_tree()
    root_b, _, _ = MerkleTreeBuilder(list(reversed(files))).build_tree()

    assert root_a == root_b  # leaves se ordenan alfabéticamente


def test_tampering_changes_root(tmp_path):
    files = _write_files(tmp_path, {"evidencia.md": "linea original"})
    root_original, _, _ = MerkleTreeBuilder(files).build_tree()

    files[0].write_text("linea MODIFICADA", encoding="utf-8")
    root_tampered, _, _ = MerkleTreeBuilder(files).build_tree()

    assert root_original != root_tampered


if __name__ == '__main__':
    # Production entry point
    pass
