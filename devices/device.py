"""MEMBER 1: simulated IIoT device, key generation and signing."""

import base64
import hashlib

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


class SimulatedDevice:
    def __init__(self, device_id: str, device_type: str, role: str = "sensor"):
        self.device_id = device_id
        self.device_type = device_type
        self.role = role
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.public_key_pem = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")
        digest = hashlib.sha256(self.public_key_pem.encode("utf-8")).hexdigest()
        self.did = f"did:iiot:{digest[:32]}"

    def sign(self, message: bytes) -> str:
        signature = self.private_key.sign(message, ec.ECDSA(hashes.SHA256()))
        return base64.b64encode(signature).decode("ascii")

