from cryptography.hazmat.primitives.hashes import SHA256, Hash


def sha256_string_hashing(string: str) -> str:
    digest = Hash(SHA256())
    digest.update(string.encode())
    return digest.finalize().hex()
