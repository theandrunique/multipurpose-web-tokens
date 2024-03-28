import mwt
from conftest import TEST_SECRET_KEY, mwt_id


def test_create_token():
    data = "data"
    purpose = b"purpose"
    token = mwt.create_token(data, TEST_SECRET_KEY, mwt_id, purpose)
    
    print(f"Generated token is: {token}")

    decoded_data, decoded_mwt_id, decoded_purpose = mwt.validate_token(token, TEST_SECRET_KEY)
    
    assert data == decoded_data
    assert mwt_id == decoded_mwt_id
    assert purpose == decoded_purpose