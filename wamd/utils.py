import os
import binascii
import zlib
import json

from google.protobuf import json_format

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .coder import decodeInt
from .errors import InvalidMediaSignature


_CRYPTO_BACKEND = default_backend()


def generateRandomNumber(length=32):
    s = str(decodeInt(os.urandom(2), 2))
    len_s = len(s)

    if len_s >= length:
        return s[:length]

    while len_s < length:
        r = str(decodeInt(os.urandom(2), 2))
        s += r[:length - len_s]
        len_s = len(s)

    return s


def toHex(data, upper=True):
    if not isinstance(data, bytes):
        data = data.encode()
    result = binascii.hexlify(data).decode()
    if upper:
        result = result.upper()
    return result


def hmacValidate(signKey, hmacSignature, data, size=None):
    h = hmac.HMAC(signKey, hashes.SHA256(), backend=_CRYPTO_BACKEND)
    h.update(data)
    signature = h.finalize()

    if size is not None:
        return signature[:10] == hmacSignature

    return signature == hmacSignature


_MEDIA_KEYS = {
    "image": b"WhatsApp Image Keys",
    "video": b"WhatsApp Video Keys",
    "audio": b"WhatsApp Audio Keys",
    "document": b"WhatsApp Document Keys",
    "history": b"WhatsApp History Keys"
}

def getMediaKeys(mediaType):
    try:
        return _MEDIA_KEYS[mediaType]
    except:
        return b""


def decryptMedia(encryptedMedia, mediaKey, mediaType):
    mediaKeyExpanded = HKDF(
        algorithm=hashes.SHA256(),
        length=112,
        salt=None,
        info=getMediaKeys(mediaType),
        backend=_CRYPTO_BACKEND
    ).derive(mediaKey)

    iv = mediaKeyExpanded[:16]
    cipherKey = mediaKeyExpanded[16:48]
    macKey = mediaKeyExpanded[48:80]

    mediaEncrypted = encryptedMedia[:-10]
    hmacSignature = encryptedMedia[-10:]

    if not hmacValidate(macKey, hmacSignature, iv + mediaEncrypted, size=10):
        raise InvalidMediaSignature("Invalid media signature")

    cipher = Cipher(algorithms.AES(cipherKey), modes.CBC(iv), backend=_CRYPTO_BACKEND)
    decryptor = cipher.decryptor()
    mediaPlain = decryptor.update(addPadding(mediaEncrypted)) + decryptor.finalize()

    return mediaPlain


def addPadding(data, padLength=16):
    length = len(data)
    if length % padLength == 0:
        return data
    return data + (b"\x00" * (16 - (length % padLength)))


_IMAGE_MIME_TYPES = [
    "image/jpeg",
    "image/png",
    "image/jpg",
    "image/webp",
    "image/tiff",
    "image/gif",
    "image/bmp"
]

_VIDEO_MIME_TYPES = [
    "video/mp4",
    "video/3gpp",
    "video/3gp",
    "video/mpeg",
    "video/ogg",
    "video/x-msvideo"
]

_AUDIO_MIME_TYPES = [
    "audio/mpeg",
    "audio/ogg",
    "audio/opus",
    "audio/wav",
    "audio/x-wav",
    "audio/webm",
]

_DOCUMENT_MIME_TYPES = [
    "application/pdf",
    "application/zip",
    "application/msword",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "text/csv",
    "text/plain",
    "application/x-tar",
    "application/vnd.ms-excel",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/x-7z-compressed",
    "application/x-bzip",
    "application/x-bzip2"
]


def mediaTypeFromMime(mime):
    if mime in _IMAGE_MIME_TYPES:
        type = "image"
    elif mime in _VIDEO_MIME_TYPES:
        type = "video"
    elif mime in _AUDIO_MIME_TYPES:
        type = "audio"
    elif mime in _DOCUMENT_MIME_TYPES:
        type = "document"
    else:
        raise ValueError("Unsupported mime: %s" % (mime, ))

    return type


def addSupportedMimeType(mime, type):
    if type == "image":
        _TYPES = _IMAGE_MIME_TYPES
    elif type == "video":
        _TYPES = _VIDEO_MIME_TYPES
    elif type == "audio":
        _TYPES = _AUDIO_MIME_TYPES
    elif type == "document":
        _TYPES = _DOCUMENT_MIME_TYPES
    else:
        raise ValueError("Unsupported type: %s" % (type, ))

    if mime not in _TYPES:
        _TYPES.append(mime)


def inflate(data):
    return zlib.decompress(data)


def protoMessageToJson(protoMessage):
    return json.loads(
        json_format.MessageToJson(protoMessage)
    )
