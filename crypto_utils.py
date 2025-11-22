"""Utilidades criptográficas centradas en hashing y generación de llaves.

Este módulo se diseñó para ser fácilmente reemplazable por bibliotecas
criptográficas reales (ej. cryptography, pyca/openssl) cuando se conecte a una
base de datos y un backend definitivo.
"""
import hashlib
import os
import secrets
from typing import Optional, Tuple


def hash_password(password: str, salt: Optional[str] = None) -> Tuple[str, str]:
    """Genera un hash SHA-256 con sal.

    Args:
        password: Contraseña en texto claro.
        salt: Sal hex opcional. Si no se proporciona se genera automáticamente.

    Returns:
        Una tupla con el hash hex y la sal utilizada.
    """
    if salt is None:
        salt = os.urandom(16).hex()
    digest = hashlib.sha256(salt.encode("utf-8") + password.encode("utf-8")).hexdigest()
    return digest, salt


def verify_password(password: str, stored_hash: str, salt: str) -> bool:
    """Verifica una contraseña contra su hash y sal almacenados."""
    candidate_hash, _ = hash_password(password, salt)
    return secrets.compare_digest(candidate_hash, stored_hash)


def generate_rsa_keypair() -> Tuple[str, str]:
    """Genera un par de llaves RSA simuladas (2048 bits) para la demo."""
    private_key = f"RSA-PRIVATE-{secrets.token_hex(32)}"
    public_key = f"RSA-PUBLIC-{secrets.token_hex(32)}"
    return public_key, private_key