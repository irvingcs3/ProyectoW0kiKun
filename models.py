from dataclasses import dataclass


@dataclass
class User:
    id: int
    username: str
    password_hash: str
    salt: str
    active: bool = True


@dataclass
class KeyPair:
    user_id: int
    public_key: str
    private_key: str


@dataclass
class CodeFile:
    id: int
    filename: str
    content: str
    owner_id: int
