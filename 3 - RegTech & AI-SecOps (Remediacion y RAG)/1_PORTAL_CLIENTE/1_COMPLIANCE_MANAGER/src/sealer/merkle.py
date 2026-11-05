#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
merkle.py - SHA-256 Merkle Tree Construction Engine.
Calculates individual artifact hashes and builds a Merkle Tree for evidence immutability.
"""

import hashlib
from pathlib import Path
from typing import List, Dict, Tuple

class MerkleTreeBuilder:
    def __init__(self, file_paths: List[Path]):
        self.file_paths = file_paths

    def calculate_file_hash(self, file_path: Path) -> str:
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(65536):
                sha256.update(chunk)
        return sha256.hexdigest()

    def build_tree(self) -> Tuple[str, Dict[str, str], List[str]]:
        leaf_hashes: Dict[str, str] = {}
        for path in self.file_paths:
            if path.is_file():
                leaf_hashes[path.name] = self.calculate_file_hash(path)

        sorted_leaves = [leaf_hashes[k] for k in sorted(leaf_hashes.keys())]
        if not sorted_leaves:
            return hashlib.sha256(b"empty").hexdigest(), {}, []

        current_level = sorted_leaves
        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i+1] if i+1 < len(current_level) else left
                combined = left + right
                parent_hash = hashlib.sha256(combined.encode("utf-8")).hexdigest()
                next_level.append(parent_hash)
            current_level = next_level

        merkle_root = current_level[0]
        return merkle_root, leaf_hashes, sorted_leaves


if __name__ == '__main__':
    # Production entry point
    pass
