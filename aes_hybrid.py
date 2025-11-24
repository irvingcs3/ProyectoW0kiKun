# aes_hybrid.py
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization


def load_public_key(pem_text: str):
    return serialization.load_pem_public_key(pem_text.encode())


def load_private_key(pem_text: str):
    return serialization.load_pem_private_key(pem_text.encode(), password=None)


# --------------------------
# CIFRAR (AES → archivo | RSA → clave AES)
# --------------------------
def cifrar_archivo_hibrido(path, public_key_pem):
    public_key = load_public_key(public_key_pem)

    clave_aes = os.urandom(32)
    iv = os.urandom(16)

    backend = default_backend()
    cipher = Cipher(algorithms.AES(clave_aes), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()

    with open(path, "rb") as f:
        datos = f.read()

    datos_padded = padder.update(datos) + padder.finalize()
    datos_cifrados = encryptor.update(datos_padded) + encryptor.finalize()

    clave_aes_cifrada = public_key.encrypt(
        clave_aes,
        rsa_padding.OAEP(mgf=rsa_padding.MGF1(None), algorithm=None, label=None)
    )

    enc_path = path + ".enc"

    with open(enc_path, "wb") as f:
        f.write(len(clave_aes_cifrada).to_bytes(4, "big"))
        f.write(clave_aes_cifrada)
        f.write(iv)
        f.write(datos_cifrados)

    return enc_path


# --------------------------
# DESCIFRAR
# --------------------------
def descifrar_archivo_hibrido(enc_path, private_key_pem):
    private_key = load_private_key(private_key_pem)

    with open(enc_path, "rb") as f:
        tam = int.from_bytes(f.read(4), "big")
        clave_cif = f.read(tam)
        iv = f.read(16)
        datos_cifrados = f.read()

    clave_aes = private_key.decrypt(
        clave_cif,
        rsa_padding.OAEP(mgf=rsa_padding.MGF1(None), algorithm=None, label=None)
    )

    backend = default_backend()
    cipher = Cipher(algorithms.AES(clave_aes), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(128).unpadder()

    datos_desc = decryptor.update(datos_cifrados) + decryptor.finalize()
    datos_final = unpadder.update(datos_desc) + unpadder.finalize()

    out_path = enc_path.replace(".enc", "_dec.txt")
    with open(out_path, "wb") as f:
        f.write(datos_final)

    return out_path
