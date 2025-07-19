from enum import Enum
import uuid
from multipurpose_web_tokens import validate_token, create_token


class CustomPurpose(Enum):
    authentication = b"1"
    email_verification = b"2"
    password_recovery = b"3"


data_to_sign = "58039284"
secret_key = b"your_secret_key"

mwt_id = uuid.uuid4()

token = create_token(
    data=data_to_sign, 
    key=secret_key, 
    mwt_id=mwt_id,
    purpose=CustomPurpose.authentication
)

print("Generated Token:", token)

dec_data, dec_mwt_id, dec_purpose = validate_token(token, secret_key, CustomPurpose)

print("Signed data:", data_to_sign)
print("Decoded data:", dec_data)

print("Decoded mwt_id:", dec_mwt_id)

print("Decoded purpose:", dec_purpose)