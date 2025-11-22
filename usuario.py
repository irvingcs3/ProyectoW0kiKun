from dataclasses import dataclass

@dataclass
class Usuario:
    id: int
    nombre_usuario: str
    password_hash: str 
    salt: str         
    esta_activo: bool = True