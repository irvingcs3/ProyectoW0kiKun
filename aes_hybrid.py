import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
from cryptography.hazmat.primitives import serialization, hashes


def load_public_key(pem_text: str):
    return serialization.load_pem_public_key(pem_text.encode())


def load_private_key(pem_text: str):
    return serialization.load_pem_private_key(pem_text.encode(), password=None)


def cifrar_archivo_hibrido(path: str, public_key_pem: str) -> str:
    public_key = load_public_key(public_key_pem)

    aes_key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12) 

    with open(path, "rb") as f:
        plaintext = f.read()

    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)

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


def cifrar_archivo_hibrido_puro(path: str, public_key_pem: str):
    
    public_key = load_public_key(public_key_pem)
    aes_key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12) 

    with open(path, "rb") as f:
        plaintext = f.read()

    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)
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
        f.write(nonce)
        f.write(ciphertext)
    
    return enc_path, encrypted_aes_key


def descifrar_archivo_hibrido(enc_path: str, private_key_pem: str) -> str:
    private_key = load_private_key(private_key_pem)

    with open(enc_path, "rb") as f:
        key_len = int.from_bytes(f.read(4), "big")
        encrypted_aes_key = f.read(key_len)
        nonce = f.read(12) 
        ciphertext = f.read()

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
    
    if isinstance(clave_aes_bytes, str):
        clave_aes_bytes = clave_aes_bytes.encode()


    if len(clave_aes_bytes) != 32:
        digest = hashes.Hash(hashes.SHA256())
        digest.update(clave_aes_bytes)
        clave_aes_bytes = digest.finalize()

    aesgcm = AESGCM(clave_aes_bytes)
    nonce = os.urandom(12) 

    with open(path_entrada, "rb") as f:
        plaintext = f.read()

    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)


    enc_path = path_entrada + ".enc"
    with open(enc_path, "wb") as f:
        f.write(nonce)
        f.write(ciphertext)

    return enc_path

def descifrar_con_aes_maestra(enc_path: str, clave_aes_bytes: bytes) -> str:

    if isinstance(clave_aes_bytes, str):
        clave_aes_bytes = clave_aes_bytes.encode()

    if len(clave_aes_bytes) != 32:
        digest = hashes.Hash(hashes.SHA256())
        digest.update(clave_aes_bytes)
        clave_aes_bytes = digest.finalize()

    aesgcm = AESGCM(clave_aes_bytes)

    with open(enc_path, "rb") as f:
        nonce = f.read(12)      
        ciphertext = f.read()   
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
    except Exception:
        raise ValueError("Error de descifrado: Llave incorrecta o archivo corrupto.")

    out_path = enc_path.replace(".enc", "_dec.txt")
    if out_path == enc_path: out_path += "_dec.txt"
    
    with open(out_path, "wb") as f:
        f.write(plaintext)

    return out_path