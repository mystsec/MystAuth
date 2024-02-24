from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import secrets
import os

def getID():
    id = secrets.token_hex(8)
    while os.path.exists('private_key_'+id+'.pem'):
        id = secrets.token_hex(8)
    return id

# 1. Generate the RSA key pair
private_key = rsa.generate_private_key(
    public_exponent=65537,  # RS256
    key_size=4096,
    backend=default_backend()
)

# 2. Export the public key
kid = getID() # Get Key ID
public_key = private_key.public_key()
public_key_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
public_path = "public_key_"+kid+".pem"
with open(public_path, "wb") as pub_file:
    pub_file.write(public_key_pem)

# 3. Export the private key
pem_path = "private_key_"+kid+".pem"
with open(pem_path, "wb") as pem_file:
    pem_file.write(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    )

print("Key ID:", kid)
#print("Public key (PEM format):\n", public_key_pem.decode())
#print("Private key saved to:", pem_path)
