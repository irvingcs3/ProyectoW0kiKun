import hashlib
import os
import secrets
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple


# --- Modelos de datos simulados (persistencia en memoria) ---
USUARIOS_REGISTRADOS: List["Usuario"] = []
NEXT_USER_ID = 1

KEY_PAIRS: Dict[int, Tuple[str, str]] = {}
ARCHIVOS_CODIGO: List["CodeFile"] = []
NEXT_FILE_ID = 1


@dataclass
class Usuario:
    id: int
    nombre_usuario: str
    password_hash: str
    salt: str
    esta_activo: bool = True


@dataclass
class CodeFile:
    id: int
    nombre_archivo: str
    contenido: str
    propietario_id: int


# --- Utilidades de seguridad ---
def hash_password(password: str, salt: Optional[str] = None) -> Tuple[str, str]:
    """Genera un hash SHA-256 con sal única para almacenar contraseñas de forma segura."""
    if salt is None:
        salt = os.urandom(16).hex()

    hashed_password = hashlib.sha256(salt.encode("utf-8") + password.encode("utf-8")).hexdigest()
    return hashed_password, salt


def change_password(usuario: Usuario, old_password: str, new_password: str) -> Tuple[bool, str]:
    """Actualiza la contraseña de un usuario verificando la anterior y devolviendo mensajes amigables."""
    if not (4 <= len(new_password) <= 20):
        return False, "La nueva contraseña debe tener entre 4 y 20 caracteres."

    hash_old, _ = hash_password(old_password, salt=usuario.salt)
    if hash_old != usuario.password_hash:
        return False, "La contraseña actual no es correcta."

    usuario.password_hash, usuario.salt = hash_password(new_password)
    return True, "La contraseña se actualizó correctamente."


def generate_rsa_keypair(usuario: Usuario) -> Tuple[str, str]:
    """Genera un par de llaves RSA ficticio para la demo (simulando 2048 bits) y lo almacena en memoria."""
    private_key = f"RSA-PRIVATE-{secrets.token_hex(32)}"
    public_key = f"RSA-PUBLIC-{secrets.token_hex(32)}"
    KEY_PAIRS[usuario.id] = (public_key, private_key)
    return public_key, private_key


def store_code_file(usuario: Usuario, nombre_archivo: str, contenido: str) -> CodeFile:
    """Simula el guardado de un archivo de código cifrado en la base de datos."""
    global NEXT_FILE_ID
    nuevo_archivo = CodeFile(
        id=NEXT_FILE_ID,
        nombre_archivo=nombre_archivo.strip() or f"archivo_{NEXT_FILE_ID}.txt",
        contenido=contenido,
        propietario_id=usuario.id,
    )
    ARCHIVOS_CODIGO.append(nuevo_archivo)
    NEXT_FILE_ID += 1
    return nuevo_archivo


def listar_archivos() -> List[CodeFile]:
    return list(ARCHIVOS_CODIGO)


def obtener_archivo_por_id(file_id: int) -> Optional[CodeFile]:
    return next((f for f in ARCHIVOS_CODIGO if f.id == file_id), None)
