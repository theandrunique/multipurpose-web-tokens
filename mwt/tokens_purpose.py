from enum import Enum


class TokenPurpose(Enum):
    authentication = b"1"
    email_verification = b"2"
    password_recovery = b"3"