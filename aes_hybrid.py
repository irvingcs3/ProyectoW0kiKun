import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
from cryptography.hazmat.primitives import serialization, hashes


# Funciones para cargar las llaves RSA desde PEM
def load_public_key(pem_text: str):
    return serialization.load_pem_public_key(pem_text.encode())


def load_private_key(pem_text: str):
    return serialization.load_pem_private_key(pem_text.encode(), password=None)



def cifrar_archivo_hibrido(path: str, public_key_pem: str) -> str:
    public_key = load_public_key(public_key_pem)

    # AES-256 GCM
    aes_key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12) 

    with open(path, "rb") as f:
        plaintext = f.read()

    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)

    # Ciframos la clave AES con RSA-OAEP-SHA256
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
        # Guardamos longitud de la clave cifrada (4 bytes)
        f.write(len(encrypted_aes_key).to_bytes(4, "big"))
        f.write(encrypted_aes_key)
        f.write(nonce)
        f.write(ciphertext)

    return enc_path


def descifrar_archivo_hibrido(enc_path: str, private_key_pem: str) -> str:
    private_key = load_private_key(private_key_pem)

    with open(enc_path, "rb") as f:
        key_len = int.from_bytes(f.read(4), "big")
        encrypted_aes_key = f.read(key_len)
        nonce = f.read(12) 
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



def cifrar_con_aes_maestra(path_entrada: str, clave_aes_bytes: bytes) -> str:
    """
    Cifra un archivo usando una clave AES específica proveniente de la Base de Datos.
    NO genera una clave nueva, usa la del Proyecto.
    """
    # 1. Asegurar formato de la clave
    if isinstance(clave_aes_bytes, str):
        clave_aes_bytes = clave_aes_bytes.encode()

    # 2. Validar longitud de clave para AES-256 (Debe ser 32 bytes)
    if len(clave_aes_bytes) != 32:
        digest = hashes.Hash(hashes.SHA256())
        digest.update(clave_aes_bytes)
        clave_aes_bytes = digest.finalize()

    # 3. Preparar cifrado
    aesgcm = AESGCM(clave_aes_bytes)
    nonce = os.urandom(12) 

    # 4. Leer archivo original
    with open(path_entrada, "rb") as f:
        plaintext = f.read()

    # 5. Cifrar
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)

    # 6. Guardar archivo cifrado (.enc)
    enc_path = path_entrada + ".enc"
    with open(enc_path, "wb") as f:
        f.write(nonce)
        f.write(ciphertext)

    return enc_path