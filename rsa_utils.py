
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import base64
from pathlib import Path

def generar_par_claves_rsa() -> tuple[str, str]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    return public_pem, private_pem


def load_private_key_from_pem(pem_text: str):
    return serialization.load_pem_private_key(pem_text.encode("utf-8"), password=None)


def load_public_key_from_pem(pem_text: str):
    return serialization.load_pem_public_key(pem_text.encode("utf-8"))


def firmar_archivo(path: str, private_pem: str) -> str:

    private_key = load_private_key_from_pem(private_pem)

    with open(path, "rb") as f:
        data = f.read()

    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )

    sig_b64 = base64.b64encode(signature)
    sig_path = str(Path(path).with_suffix(Path(path).suffix + ".sig"))

    with open(sig_path, "wb") as f:
        f.write(sig_b64)

    return sig_path


def verificar_firma(path: str, sig_path: str, public_pem: str) -> bool:

    public_key = load_public_key_from_pem(public_pem)

    with open(path, "rb") as f:
        data = f.read()
    with open(sig_path, "rb") as f:
        signature = base64.b64decode(f.read())

    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False
