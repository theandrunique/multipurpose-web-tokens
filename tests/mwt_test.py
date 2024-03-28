import base64
from uuid import uuid4
import mwt
from mwt.exceptions import InvalidToken
from conftest import TEST_SECRET_KEY, mwt_id
import pytest

from mwt.utils import align_b64


def test_create_token():
    data = "data"
    purpose = b"purpose"
    token = mwt.create_token(data, TEST_SECRET_KEY, mwt_id, purpose)
    
    print(f"Generated token is: {token}")

    decoded_data, decoded_mwt_id, decoded_purpose = mwt.validate_token(token, TEST_SECRET_KEY)
    
    assert data == decoded_data
    assert mwt_id == decoded_mwt_id
    assert purpose == decoded_purpose


def test_invalid_token():
    with pytest.raises(InvalidToken):
        mwt.validate_token("invalid-token.efsdf.fsdlfhiosdf", TEST_SECRET_KEY)


def test_create_token_and_change_content():
    data = "data"
    purpose = b"purpose"
    token = mwt.create_token(data, TEST_SECRET_KEY, mwt_id, purpose)
    
    data, payload, signature = token.split(".")
    
    purpose, mwt_id_bytes = base64.urlsafe_b64decode(align_b64(payload)).split(b":")
    new_mwt_id_bytes = uuid4().bytes
    new_payload = base64.urlsafe_b64encode(purpose + b":" + new_mwt_id_bytes)
    
    interrupted_token = f"{data}.{new_payload}.{signature}"
    
    with pytest.raises(InvalidToken):
        mwt.validate_token(interrupted_token, TEST_SECRET_KEY)