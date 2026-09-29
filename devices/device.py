"""Simulated IIoT device.

MEMBER 1:
- ECC P-256 key generation
- DID generation
- PSK authentication response
- Proof-of-possession signature
- Resource-request signatures
"""

import base64
import hashlib
import hmac

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


class SimulatedDevice:
    def __init__(
        self,
        device_id: str,
        device_type: str,
        psk: str = "test-device-psk",
        role: str = "sensor",
        zone: str = "zone-1",
    ):
        self.device_id = device_id
        self.device_type = device_type
        self.psk = psk
        self.role = role
        self.zone = zone

        # The private key remains on the device.
        self.private_key = ec.generate_private_key(ec.SECP256R1())

        # Only this public key is sent to the fog.
        self.public_key_pem = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

        # DID is derived from the public key.
        public_key_hash = hashlib.sha256(
            self.public_key_pem.encode("utf-8")
        ).hexdigest()

        self.did = f"did:iiot:{public_key_hash[:32]}"

    @property
    def public_key_thumbprint(self) -> str:
        """Return SHA-256 fingerprint of the public key."""

        return hashlib.sha256(
            self.public_key_pem.encode("utf-8")
        ).hexdigest()

    def create_psk_response(self, nonce: str) -> str:
        """Create HMAC-SHA256 response for initial authentication.

        Message:
            device_id || nonce
        """

        message = f"{self.device_id}|{nonce}".encode("utf-8")

        return hmac.new(
            self.psk.encode("utf-8"),
            message,
            hashlib.sha256,
        ).hexdigest()

    def sign(self, message: bytes) -> str:
        """Sign bytes using the device's ECC private key."""

        signature = self.private_key.sign(
            message,
            ec.ECDSA(hashes.SHA256()),
        )

        return base64.b64encode(signature).decode("ascii")

    def sign_challenge(self, challenge: str) -> str:
        """Sign the fog's proof-of-possession challenge."""

        return self.sign(challenge.encode("utf-8"))

    def build_signed_request(
        self,
        resource: str,
        operation: str,
        body_hash: str,
        nonce: str,
        timestamp: int,
        token_jti: str = "",
    ) -> dict:
        """Create a signed resource request.

        The exact signed format is defined in docs/CONTRACTS.md.
        """

        canonical_message = (
            f"{self.did}|"
            f"{resource}|"
            f"{operation.upper()}|"
            f"{body_hash}|"
            f"{nonce}|"
            f"{timestamp}|"
            f"{token_jti}"
        )

        return {
            "did": self.did,
            "resource": resource,
            "operation": operation.upper(),
            "body_hash": body_hash,
            "nonce": nonce,
            "timestamp": timestamp,
            "signature": self.sign(canonical_message.encode("utf-8")),
        }