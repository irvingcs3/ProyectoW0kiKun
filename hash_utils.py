import hashlib

def hash_archivo(path):
    sha = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(4096):
            sha.update(chunk)
    h = sha.hexdigest()

    with open(path + ".hash", "w") as f:
        f.write(h)

    return h
