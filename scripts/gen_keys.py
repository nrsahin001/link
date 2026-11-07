"""Generate the RSA key that signs ID tokens.  Run once; keep the file secret and backed up."""
import os
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

path = sys.argv[1] if len(sys.argv) > 1 else "keys/oidc_private.pem"
if os.path.exists(path):
    sys.exit(f"{path} already exists - refusing to overwrite (that would invalidate issued tokens).")
os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                        serialization.NoEncryption())
fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, "wb") as f:
    f.write(pem)
print(f"Wrote {path}")
