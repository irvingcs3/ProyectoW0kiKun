# aes_hybrid.py
# ---------------------------------------------------------
# Cifrado híbrido:
#   - AES-256 en modo GCM (AEAD: confidencialidad + autenticidad)
#   - RSA-OAEP con SHA-256 para cifrar la clave AES
# Formato del archivo .enc:
#   [4 bytes: len_claveRSA][claveAES_cifrada][12 bytes: nonce][ciphertext+tag]
# ---------------------------------------------------------

import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
from cryptography.hazmat.primitives import serialization, hashes


# --------------------------
# Helpers para cargar llaves
# --------------------------
def load_public_key(pem_text: str):
    return serialization.load_pem_public_key(pem_text.encode())


def load_private_key(pem_text: str):
    return serialization.load_pem_private_key(pem_text.encode(), password=None)


# --------------------------
# CIFRAR (AES-GCM + RSA-OAEP)
# --------------------------
def cifrar_archivo_hibrido(path: str, public_key_pem: str) -> str:
    """
    Cifra un archivo usando:
      - AES-256 GCM para el contenido
      - RSA-OAEP-SHA256 para la clave AES

    :param path: Ruta del archivo original en texto claro.
    :param public_key_pem: Llave pública RSA del usuario (PEM).
    :return: Ruta del archivo cifrado (.enc).
    """
    public_key = load_public_key(public_key_pem)

    # AES-256 GCM
    aes_key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)  # tamaño recomendado para GCM

    with open(path, "rb") as f:
        plaintext = f.read()

    # ciphertext incluye también el tag autenticado
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)

    # Cifrar la clave AES con RSA-OAEP-SHA256
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
        # Guardar longitud de la clave cifrada (4 bytes, big endian)
        f.write(len(encrypted_aes_key).to_bytes(4, "big"))
        f.write(encrypted_aes_key)
        f.write(nonce)
        f.write(ciphertext)

    return enc_path


# --------------------------
# DESCIFRAR
# --------------------------
def descifrar_archivo_hibrido(enc_path: str, private_key_pem: str) -> str:
    """
    Descifra un archivo generado con cifrar_archivo_hibrido.

    :param enc_path: Ruta del archivo cifrado (.enc).
    :param private_key_pem: Llave privada RSA del usuario (PEM).
    :return: Ruta del archivo descifrado (_dec.txt).
    """
    private_key = load_private_key(private_key_pem)

    with open(enc_path, "rb") as f:
        key_len = int.from_bytes(f.read(4), "big")
        encrypted_aes_key = f.read(key_len)
        nonce = f.read(12)  # mismo tamaño usado en el cifrado
        ciphertext = f.read()

    # Recuperar la clave AES con RSA-OAEP-SHA256
    aes_key = private_key.decrypt(
        encrypted_aes_key,
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    aesgcm = AESGCM(aes_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=None)

    out_path = enc_path.replace(".enc", "_dec.txt")
    with open(out_path, "wb") as f:
        f.write(plaintext)

    return out_path
