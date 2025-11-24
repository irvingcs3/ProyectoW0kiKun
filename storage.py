"""Simulador de base de datos para usuarios, llaves y archivos de código.

Cada función incluye comentarios sobre el punto exacto donde se haría la
inserción o consulta SQL cuando se sustituya por una base real.
"""
from typing import Dict, List, Optional, Tuple
from rsa_utils import generar_par_claves_rsa
from crypto_utils import generate_rsa_keypair, hash_password, verify_password
from models import CodeFile, KeyPair, User

def generate_and_store_keys(user: User) -> KeyPair:
    public_key, private_key = generar_par_claves_rsa()  # ahora usa RSA real
    keypair = KeyPair(user_id=user.id, public_key=public_key, private_key=private_key)
    _DATABASE["llaves"][user.id] = keypair
    return keypair

# --- Estructuras simuladas (sustituibles por una DB real) ---
_DATABASE: Dict[str, object] = {
    "usuarios": [],  # type: List[User]
    "llaves": {},  # type: Dict[int, KeyPair]
    "archivos": [],  # type: List[CodeFile]
    "next_user_id": 1,
    "next_file_id": 1,
}


# --- Operaciones sobre usuarios ---
def create_user(username: str, password: str) -> Tuple[bool, str, Optional[User]]:
    """Crea un usuario aplicando hash con sal.

    TODO: Reemplazar con un INSERT INTO usuarios (username, password_hash, salt)
    y retornar el registro creado.
    """
    if not (4 <= len(password) <= 20):
        return False, "La contraseña debe tener entre 4 y 20 caracteres.", None

    if any(u.username == username for u in _DATABASE["usuarios"]):
        return False, f"El usuario '{username}' ya existe.", None

    password_hash, salt = hash_password(password)
    user_id = _DATABASE["next_user_id"]
    _DATABASE["next_user_id"] += 1

    user = User(id=user_id, username=username, password_hash=password_hash, salt=salt)
    _DATABASE["usuarios"].append(user)
    return True, f"Usuario '{username}' creado con ID {user_id}", user


def find_user_by_username(username: str) -> Optional[User]:
    """Busca un usuario por nombre.

    TODO: SELECT * FROM usuarios WHERE username = ?
    """
    return next((u for u in _DATABASE["usuarios"] if u.username == username), None)


def authenticate(username: str, password: str) -> Tuple[bool, str, Optional[User]]:
    """Valida credenciales contra el almacén de hashes."""
    user = find_user_by_username(username)
    if not user:
        return False, "Usuario o contraseña incorrectos.", None

    if not verify_password(password, user.password_hash, user.salt):
        return False, "Usuario o contraseña incorrectos.", None

    return True, f"Bienvenido, {user.username}.", user


def update_password(user: User, old_password: str, new_password: str) -> Tuple[bool, str]:
    """Cambia la contraseña verificando la anterior."""
    if not verify_password(old_password, user.password_hash, user.salt):
        return False, "La contraseña actual no es correcta."
    if not (4 <= len(new_password) <= 20):
        return False, "La nueva contraseña debe tener entre 4 y 20 caracteres."

    new_hash, new_salt = hash_password(new_password)
    user.password_hash = new_hash
    user.salt = new_salt

    # TODO: UPDATE usuarios SET password_hash = ?, salt = ? WHERE id = ?
    return True, "Contraseña actualizada correctamente."


# # --- Operaciones sobre llaves RSA ---
# def generate_and_store_keys(user: User) -> KeyPair:
#     """Genera y guarda el par de llaves para el usuario."""
#     public_key, private_key = generate_rsa_keypair()
#     keypair = KeyPair(user_id=user.id, public_key=public_key, private_key=private_key)
#     _DATABASE["llaves"][user.id] = keypair
#     # TODO: INSERT INTO llaves(usuario_id, public_key, private_key)
#     return keypair


def get_keys_for_user(user: User) -> Optional[KeyPair]:
    """Recupera el par de llaves de un usuario."""
    return _DATABASE["llaves"].get(user.id)


# --- Operaciones sobre archivos de código ---
def store_code_file(user: User, filename: str, content: str) -> CodeFile:
    """Guarda un archivo de código (contenido simulado ya cifrado)."""
    file_id = _DATABASE["next_file_id"]
    _DATABASE["next_file_id"] += 1

    cleaned_name = filename.strip() or f"archivo_{file_id}.txt"
    codefile = CodeFile(id=file_id, filename=cleaned_name, content=content, owner_id=user.id)
    _DATABASE["archivos"].append(codefile)

    # TODO: INSERT INTO archivos(id, filename, content, owner_id)
    return codefile


def list_code_files() -> List[CodeFile]:
    """Lista todos los archivos simulados."""
    return list(_DATABASE["archivos"])


def get_code_file(file_id: int) -> Optional[CodeFile]:
    """Obtiene un archivo por ID."""
    return next((f for f in _DATABASE["archivos"] if f.id == file_id), None)


# --- Datos semilla de demostración ---
def seed_demo_user() -> User:
    """Crea un usuario de demostración para pruebas rápidas."""
    existing = find_user_by_username("lider")
    if existing:
        return existing

    created, _, user = create_user("lider", "123456")
    assert created and user is not None
    return user
