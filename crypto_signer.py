import json
import base64
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

class CryptoSigner:
    """Ed25519 Digital Signing Service for License Entitlements."""

    def __init__(self, keys_dir: Path):
        self.keys_dir = Path(keys_dir)
        self.keys_dir.mkdir(parents=True, exist_ok=True)
        self.private_key_path = self.keys_dir / 'ed25519_private.pem'
        self.public_key_path = self.keys_dir / 'ed25519_public.pem'
        self._load_or_generate_keys()

    def _load_or_generate_keys(self):
        if self.private_key_path.exists() and self.public_key_path.exists():
            private_bytes = self.private_key_path.read_bytes()
            self.private_key = serialization.load_pem_private_key(private_bytes, password=None)
            public_bytes = self.public_key_path.read_bytes()
            self.public_key = serialization.load_pem_public_key(public_bytes)
        else:
            self.private_key = ed25519.Ed25519PrivateKey.generate()
            self.public_key = self.private_key.public_key()

            # Save private key securely
            priv_pem = self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            self.private_key_path.write_bytes(priv_pem)

            # Save public key
            pub_pem = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            self.public_key_path.write_bytes(pub_pem)

    def canonical_bytes(self, payload: dict) -> bytes:
        """Deterministic UTF-8 JSON representation for signing."""
        return json.dumps(payload, sort_keys=True, separators=(',', ':')).encode('utf-8')

    def sign(self, payload: dict) -> str:
        """Signs payload and returns base64 string."""
        raw_bytes = self.canonical_bytes(payload)
        sig = self.private_key.sign(raw_bytes)
        return base64.b64encode(sig).decode('ascii')

    def verify(self, payload: dict, signature_b64: str) -> bool:
        """Verifies signature against payload."""
        try:
            raw_bytes = self.canonical_bytes(payload)
            sig = base64.b64decode(signature_b64)
            self.public_key.verify(sig, raw_bytes)
            return True
        except (InvalidSignature, Exception):
            return False

    def get_public_key_pem(self) -> str:
        return self.public_key_path.read_text(encoding='utf-8').strip()

    def get_public_key_base64(self) -> str:
        raw = self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        return base64.b64encode(raw).decode('ascii')
