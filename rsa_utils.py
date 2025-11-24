# rsa_utils.py
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import base64


# --------------------------
# Generar par de llaves RSA
# --------------------------
def generar_par_claves_rsa():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

    return public_pem, private_pem


# --------------------------
# Cargar llaves PEM
# --------------------------
def load_private_key_from_pem(pem_text: str):
    return serialization.load_pem_private_key(pem_text.encode(), password=None)


def load_public_key_from_pem(pem_text: str):
    return serialization.load_pem_public_key(pem_text.encode())


# --------------------------
# Firmar archivo
# --------------------------
def firmar_archivo(path, private_pem):
    private_key = load_private_key_from_pem(private_pem)

    with open(path, "rb") as f:
        data = f.read()

    signature = private_key.sign(
        data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )

    sig_b64 = base64.b64encode(signature)
    sig_path = path + ".sig"

    with open(sig_path, "wb") as f:
        f.write(sig_b64)

    return sig_path


# --------------------------
# Verificar firma
# --------------------------
def verificar_firma(path, sig_path, public_pem):
    public_key = load_public_key_from_pem(public_pem)

    with open(path, "rb") as f:
        data = f.read()
    with open(sig_path, "rb") as f:
        signature = base64.b64decode(f.read())

    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False
