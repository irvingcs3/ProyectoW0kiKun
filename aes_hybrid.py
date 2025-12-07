import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
from cryptography.hazmat.primitives import serialization, hashes


# ================================
# CARGA DE LLAVES RSA
# ================================
def load_public_key(pem_text: str):
    return serialization.load_pem_public_key(pem_text.encode())


def load_private_key(pem_text: str):
    return serialization.load_pem_private_key(pem_text.encode(), password=None)


# ==========================================================
#  CIFRADO HÍBRIDO LEGACY (ya NO se usa, pero lo dejamos)
# ==========================================================
def cifrar_archivo_hibrido(path: str, public_key_pem: str) -> str:
    public_key = load_public_key(public_key_pem)

    aes_key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)

    with open(path, "rb") as f:
        plaintext = f.read()

    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    encrypted_aes_key = public_key.encrypt(
        aes_key,
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    enc_path = path + ".enc"
    with open(enc_path, "wb") as f:
        f.write(len(encrypted_aes_key).to_bytes(4, "big"))
        f.write(encrypted_aes_key)
        f.write(nonce)
        f.write(ciphertext)

    return enc_path


# ==========================================================
#   CIFRADO HÍBRIDO REAL (AES + RSA)
# ==========================================================
def cifrar_archivo_hibrido_puro(path: str, public_key_pem: str):
    """
    Devuelve:
    - ruta del archivo cifrado
    - clave AES cifrada con RSA (para guardar en BD)
    """
    public_key = load_public_key(public_key_pem)

    aes_key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)

    with open(path, "rb") as f:
        plaintext = f.read()

    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    encrypted_aes_key = public_key.encrypt(
        aes_key,
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    enc_path = path + ".enc"

    with open(enc_path, "wb") as f:
        f.write(len(encrypted_aes_key).to_bytes(4, "big"))  # longitud
        f.write(encrypted_aes_key)
        f.write(nonce)
        f.write(ciphertext)

    return enc_path, encrypted_aes_key


# ==========================================================
#   DESCIFRADO HÍBRIDO REAL
# ==========================================================
def descargar_archivo_hibrido(enc_path, private_key_pem, encrypted_aes_key):
    """
    1. Descifra AES usando la clave RSA privada
    2. Descifra el archivo usando AES-GCM
    """

    private_key = load_private_key(private_key_pem)

    # Paso 1: Descifrar la clave AES
    aes_key = private_key.decrypt(
        encrypted_aes_key,
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    aesgcm = AESGCM(aes_key)

    # Paso 2: Leer el archivo cifrado correctamente
    with open(enc_path, "rb") as f:
        key_len = int.from_bytes(f.read(4), "big")   # leer longitud
        f.read(key_len)                              # saltar la clave AES cifrada del archivo
        nonce = f.read(12)
        ciphertext = f.read()

    plaintext = aesgcm.decrypt(nonce, ciphertext, None)

    out_path = enc_path.replace(".enc", "_dec.txt")
    with open(out_path, "wb") as f:
        f.write(plaintext)

    return out_path
