from uuid import uuid4

from fog.database import SessionLocal
from fog.models import Device, RevokedDevice
from fog.revocation import is_device_revoked, revoke_device


def create_test_device(db):
    unique_value = uuid4().hex

    device = Device(
        device_id=f"TEST-{unique_value}",
        did=f"did:iiot:{unique_value}",
        public_key="test-public-key",
        public_key_thumbprint=unique_value,
        device_type="temperature_sensor",
        role="sensor",
        zone="zone-1",
        status="ACTIVE",
        authentication_complete=True,
        pop_verified=True,
    )

    db.add(device)
    db.commit()
    db.refresh(device)

    return device


def test_device_can_be_revoked():
    db = SessionLocal()
    device = None

    try:
        device = create_test_device(db)

        result = revoke_device(
            device.did,
            "Security test",
            db,
        )

        db.refresh(device)

        assert result["success"] is True
        assert result["code"] == "DEVICE_REVOKED"
        assert device.status == "REVOKED"
        assert is_device_revoked(device.did, db)

    finally:
        if device is not None:
            db.query(RevokedDevice).filter(
                RevokedDevice.did == device.did
            ).delete()

            db.query(Device).filter(
                Device.did == device.did
            ).delete()

            db.commit()

        db.close()


def test_revoking_same_device_twice_is_safe():
    db = SessionLocal()
    device = None

    try:
        device = create_test_device(db)

        first_result = revoke_device(
            device.did,
            "First revocation",
            db,
        )

        second_result = revoke_device(
            device.did,
            "Second attempt",
            db,
        )

        assert first_result["code"] == "DEVICE_REVOKED"
        assert (
            second_result["code"]
            == "DEVICE_ALREADY_REVOKED"
        )

    finally:
        if device is not None:
            db.query(RevokedDevice).filter(
                RevokedDevice.did == device.did
            ).delete()

            db.query(Device).filter(
                Device.did == device.did
            ).delete()

            db.commit()

        db.close()