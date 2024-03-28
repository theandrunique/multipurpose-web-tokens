import base64
import hashlib
import hmac
from uuid import UUID

from .exceptions import InvalidSignature, InvalidStructure
from .utils import align_b64, validate_hmac

def create_token(data: str, key: bytes, mwt_id: UUID, purpose: bytes) -> str:
    # encoding segments
    segments = [
        base64.urlsafe_b64encode(data.encode('utf-8')).rstrip(b'='),
        base64.urlsafe_b64encode(purpose.value + b":" + mwt_id.bytes).rstrip(b'=')
    ]
    # creating and encoding hmac
    segments.append(
        base64.urlsafe_b64encode(
            hmac.new(
                key=key, 
                msg=b".".join(segments), 
                digestmod=hashlib.sha512,
            ).digest()
        ).rstrip(b'=')
    )
    return b".".join(segments).decode("utf-8")


def validate_token(token: str, key: bytes) -> tuple[str, UUID, bytes]:
    try:
        # segmentation
        data_b64, purpose_b64, signature_b64 = token.split('.')
        payload = base64.urlsafe_b64decode(align_b64(purpose_b64))
        purpose, mwt_id_bytes = payload.split(b":")
    except Exception:
        raise InvalidStructure("Invalid structure")
    # align and decoding
    data = base64.urlsafe_b64decode(align_b64(data_b64))
    signature = base64.urlsafe_b64decode(align_b64(signature_b64))
    mwt_id = UUID(bytes=mwt_id_bytes)

    # check signature
    if not validate_hmac(
        key=key,
        received_hmac=signature,
        message=f"{data_b64}.{purpose_b64}".encode(),
    ):
        raise InvalidSignature("Invalid signature")

    return data.decode("utf-8"), mwt_id 


