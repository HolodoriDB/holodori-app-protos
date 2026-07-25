#!/usr/bin/env python3
"""decrypt an il2cpp global-metadata.dat that is xor'd with a key embedded in libil2cpp.so

first 4 key bytes come from the known metadata magic (0xFAB11BAF), the full key is found inside
the .so, and the result is verified by a fixed grpc string. if that fails the key end is found by
scanning to the next null terminator and backtracking to the first non-alphanumeric byte

    python metadata_decrypt.py <global-metadata.dat> <libil2cpp.so> [output.dat]
"""
from __future__ import annotations

import sys
from pathlib import Path

# stable grpc-library string longer than the key, present in the decrypted metadata, verifies the key
_SENTINEL = (
    b"Failed to deserialize response message. The response header contains a gRPC status of OK, "
    b"which means any message returned to the client for this call should be ignored. A unary or "
    b"client streaming gRPC call must have a response message, which makes this response invalid."
)

_ALNUM = set(b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")


def _try_decrypt(content: bytes, key: bytes) -> bytes | None:
    n = len(content)
    tiled = key * (n // len(key)) + key[: n % len(key)]
    res = (int.from_bytes(content, "big") ^ int.from_bytes(tiled, "big")).to_bytes(
        n, "big"
    )
    return res if _SENTINEL in res else None


def decrypt(metadata: bytes, lib: bytes) -> bytes:
    """decrypted metadata, raising if the key can't be found or verified"""
    key_start = bytes(
        (metadata[0] ^ 0xAF, metadata[1] ^ 0x1B, metadata[2] ^ 0xB1, metadata[3] ^ 0xFA)
    )
    idx = lib.find(key_start)
    if idx == -1:
        raise RuntimeError("couldn't find the xor key start in libil2cpp.so")

    # key is usually 128 bytes, else find its end at the next null, backtracking to the first non-alnum byte
    content = _try_decrypt(metadata, lib[idx : idx + 128])
    if content is None:
        null_idx = lib.find(b"\x00", idx)
        end_idx = None
        for i in range(null_idx - 1, idx, -1):
            if lib[i] not in _ALNUM:
                end_idx = i
                break
        if end_idx is None:
            raise RuntimeError("couldn't find the xor key end in libil2cpp.so")
        content = _try_decrypt(metadata, lib[idx : end_idx + 1])
    if content is None:
        raise RuntimeError("failed to decrypt metadata (sentinel not found)")
    return content


def decrypt_file(metadata_path: Path, lib_path: Path, out_path: Path) -> None:
    out_path.write_bytes(decrypt(metadata_path.read_bytes(), lib_path.read_bytes()))


def main() -> None:
    metadata_path = Path(sys.argv[1])
    lib_path = Path(sys.argv[2])
    out_path = (
        Path(sys.argv[3])
        if len(sys.argv) > 3
        else metadata_path.with_name("global-metadata-decrypt.dat")
    )
    decrypt_file(metadata_path, lib_path, out_path)
    print(f"[metadata_decrypt] {out_path}")


if __name__ == "__main__":
    main()
