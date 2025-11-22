import hashlib
import os

USUARIOS_REGISTRADOS = []
NEXT_USER_ID = 1

def hash_password(password: str, salt: str = None) -> (str, str):
    """
    Función que genera un hash seguro con un salt único.
    Simula el trabajo de algoritmos robustos (bcrypt/Argon2).
    """
    if salt is None:
        salt = os.urandom(16).hex()
    
    hashed_password = hashlib.sha256(
        salt.encode('utf-8') + password.encode('utf-8')
    ).hexdigest()
    
    return hashed_password, salt