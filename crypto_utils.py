import hashlib
import os
import secrets
from typing import Optional, Tuple
from rsa_utils import generar_par_claves_rsa
from hash_utils import hash_archivo

def generate_rsa_keypair():
    return generar_par_claves_rsa()

def hash_password(password: str, salt: Optional[str] = None) -> Tuple[str, str]:
    if salt is None:
        salt = os.urandom(16).hex()
    digest = hashlib.sha256(salt.encode("utf-8") + password.encode("utf-8")).hexdigest()
    return digest, salt


def verify_password(password: str, stored_hash: str, salt: str) -> bool:
    candidate_hash, _ = hash_password(password, salt)
    return secrets.compare_digest(candidate_hash, stored_hash)


