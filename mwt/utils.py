import hashlib
import hmac


def align_b64(b64_string):
    missing = len(b64_string) % 4
    return f"{b64_string}{'=' * missing}"


def validate_hmac(key: bytes, received_hmac: bytes, message: bytes):
    calculated_hmac = hmac.new(
        key=key, 
        msg=message,
        digestmod=hashlib.sha512
    ).digest()
    return hmac.compare_digest(calculated_hmac, received_hmac)
