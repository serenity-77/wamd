import os
import binascii
import zlib
import json
import magic
import time
import random
import math


from twisted.python import procutils
from twisted.internet.defer import Deferred, maybeDeferred, succeed
from twisted.internet.utils import getProcessOutput, _UnexpectedErrorOutput

from google.protobuf import json_format

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from io import BytesIO
from PIL import Image

from .errors import InvalidMediaSignature
from .constants import Constants


_CRYPTO_BACKEND = default_backend()


def generateRandomNumber(length=32):
    s = str(decodeUint(os.urandom(2), 2))
    len_s = len(s)

    if len_s >= length:
        return s[:length]

    while len_s < length:
        r = str(decodeUint(os.urandom(2), 2))
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


def toCommaSeparatedNumber(data):
    if not isinstance(data, bytes):
        data = data.encode()
    return ",".join([str(l) for l in data])

def hmacValidate(signKey, hmacSignature, data, size=None):
    h = hmac.HMAC(signKey, hashes.SHA256(), backend=_CRYPTO_BACKEND)
    h.update(data)
    signature = h.finalize()

    if size is not None:
        return signature[:10] == hmacSignature

    return signature == hmacSignature


def getMediaInfoKey(mediaType):
    try:
        return Constants.MEDIA_INFO_KEYS[mediaType]
    except KeyError:
        raise ValueError("Unsupported Media Type: %s" % (mediaType, ))


def decryptMedia(encryptedMedia, mediaKey, mediaType):
    mediaKeyExpanded = HKDF(
        algorithm=hashes.SHA256(),
        length=112,
        salt=None,
        info=getMediaInfoKey(mediaType),
        backend=_CRYPTO_BACKEND
    ).derive(mediaKey)

    iv = mediaKeyExpanded[:16]
    cipherKey = mediaKeyExpanded[16:48]
    macKey = mediaKeyExpanded[48:80]

    mediaEncrypted = encryptedMedia[:-10]
    hmacSignature = encryptedMedia[-10:]

    if not hmacValidate(macKey, hmacSignature, iv + mediaEncrypted, size=10):
        raise InvalidMediaSignature("Media Hmac Validation Failed")

    cipher = Cipher(algorithms.AES(cipherKey), modes.CBC(iv), backend=_CRYPTO_BACKEND)
    decryptor = cipher.decryptor()
    mediaPlain = decryptor.update(addPadding(mediaEncrypted)) + decryptor.finalize()

    return mediaPlain


def addPadding(data, padLength=16):
    padN = 16 - (len(data) % padLength)
    return data + bytes([padN] * padN)


def mediaTypeFromMime(mime):
    if mime in Constants.IMAGE_MIME_TYPES:
        mediaType = "image"
    elif mime in Constants.VIDEO_MIME_TYPES:
        mediaType = "video"
    elif mime in Constants.AUDIO_MIME_TYPES:
        mediaType = "audio"
    elif mime in Constants.DOCUMENT_MIME_TYPES:
        mediaType = "document"
    else:
        raise ValueError("Unsupported mime: %s" % (mime, ))

    return mediaType


def addSupportedMimeType(mime, type):
    if type == "image":
        _TYPES = Constants.IMAGE_MIME_TYPES
    elif type == "video":
        _TYPES = Constants.VIDEO_MIME_TYPES
    elif type == "audio":
        _TYPES = Constants.AUDIO_MIME_TYPES
    elif type == "document":
        _TYPES = Constants.DOCUMENT_MIME_TYPES
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


def jsonToProtoMessage(jsonDict, protoFactory):
    return json_format.ParseDict(
        jsonDict, protoFactory(), ignore_unknown_fields=True)


def sha256Hash(data):
    digest = hashes.Hash(hashes.SHA256(), backend=_CRYPTO_BACKEND)
    digest.update(data)
    return digest.finalize()


def mimeTypeFromBuffer(buffer):
    return magic.from_buffer(buffer, mime=True)


def encryptMedia(mediaBytes, mediaType):
    mediaKey = os.urandom(32)

    mediaKeyExpanded = HKDF(
        algorithm=hashes.SHA256(),
        length=112,
        salt=None,
        info=getMediaInfoKey(mediaType),
        backend=_CRYPTO_BACKEND
    ).derive(mediaKey)

    iv = mediaKeyExpanded[:16]
    cipherKey = mediaKeyExpanded[16:48]
    macKey = mediaKeyExpanded[48:80]

    cipher = Cipher(algorithms.AES(cipherKey), modes.CBC(iv), backend=_CRYPTO_BACKEND)
    encryptor = cipher.encryptor()
    enc = encryptor.update(addPadding(mediaBytes)) + encryptor.finalize()

    h = hmac.HMAC(macKey, hashes.SHA256(), backend=_CRYPTO_BACKEND)
    h.update(iv + enc)
    hmacSha256 = h.finalize()
    mac = hmacSha256[:10]

    digestEncMac = hashes.Hash(hashes.SHA256(), backend=_CRYPTO_BACKEND)
    digestEncMac.update(enc + mac)
    fileEncSha256 = digestEncMac.finalize()

    return {
        'mediaKey': mediaKey,
        'enc': enc,
        'mac': mac,
        'mediaKeyTimestamp': int(time.time()),
        'fileEncSha256': fileEncSha256
    }


def processImage(imageBytes, mimeType):
    imageIO = BytesIO(imageBytes)
    image = Image.open(imageIO)

    mediaHeight = image.height
    mediaWidth = image.width

    image.thumbnail((100, 200), Image.ANTIALIAS)
    thumbnailIO = BytesIO()

    if mimeType == "image/png":
        format = "PNG"
    elif mimeType == "image/jpg" or mimeType == "image/jpeg":
        format = "JPEG"
    else:
        format = None

    image.save(thumbnailIO, format=format)
    thumbnail = thumbnailIO.getvalue()

    imageIO.close()
    thumbnailIO.close()
    image.close()

    return mediaHeight, mediaWidth, thumbnail


def addRandomPadding(data):
    n = 1 + (15 & random.randint(1, 255))
    return data + (bytes([n] * n))


def removeRandomPadding(data):
    n = data[-1]
    return data[:-n]


try:
    _FFMPEG_EXECUTABLE = procutils.which("ffmpeg")[0]
except IndexError:
    _FFMPEG_EXECUTABLE = None

try:
    _FFPROBE_EXECUTABLE = procutils.which("ffprobe")[0]
except IndexError:
    _FFPROBE_EXECUTABLE = None


class FFMPEGAdapterError(Exception):
    pass


class FFMPEGVideoAdapter:

    _isReady = False
    _info = None

    readyDeferred = None

    def __init__(self, filepath, reactor=None):
        if not _FFMPEG_EXECUTABLE:
            raise RuntimeError("ffmpeg executable not found")

        if not _FFPROBE_EXECUTABLE:
            raise RuntimeError("ffprobe executable not found")

        self._filepath = filepath

        if reactor is None:
            from twisted.internet import reactor
        self._reactor = reactor

        self._reactor.callLater(0, self._ffprobeInfo)

    @classmethod
    def fromBytes(cls, data, reactor=None):
        path = os.path.join("/tmp/", binascii.hexlify(os.urandom(16)).decode())

        with open(path, "wb") as fileIO:
            fileIO.write(data)

        return cls(path, reactor=reactor)

    @property
    def info(self):
        if self._info is None:
            return None
        return self._info.copy()

    def ready(self):
        if self._isReady:
            return succeed(None)
        d = self.readyDeferred = Deferred()
        return d

    def saveFrame(self, fileIO, duration, format="jpeg"):
        if not self._isReady:
            raise RuntimeError("Not Ready yet")

        if format == "jpeg":
            format = "jpg"

        if format not in ["jpg", "png"]:
            raise ValueError("Invalid format %s" % (format, ))

        # Fuck it
        outputFilename = "{}.{}".format(
            binascii.hexlify(os.urandom(16)).decode(),
            format)

        outputPath = os.path.join("/tmp/", outputFilename)

        duration = str(math.floor(duration))

        args = "-y -v error -i {input} -ss {duration} -vframes 1 {output}"

        def callback(ign):
            if os.path.exists(outputPath):
                with open(outputPath, "rb") as outputIO:
                    b = outputIO.read()
                    fileIO.write(b)
                try:
                    os.remove(outputPath)
                except:
                    pass
            else:
                raise FFMPEGAdapterError("Frame save failed")

        d = self._run(
            _FFMPEG_EXECUTABLE,
            args=args.format(
                input=self._filepath,
                duration=duration,
                output=outputPath
            ).split())

        return d.addCallback(callback)


    def _ffprobeInfo(self):
        args="-v error -print_format json -show_format".split()
        args.append(self._filepath)

        def errback(failure):
            d, self.readyDeferred = self.readyDeferred, None
            d.errback(failure)

        d = self._run(_FFPROBE_EXECUTABLE, args)

        d.addCallback(self._ffprobeInfoDone)
        d.addErrback(errback)

    def _ffprobeInfoDone(self, result):
        self._info = json.loads(result)
        self._info['format']['duration'] = float(self._info['format']['duration'])
        self._isReady = True
        d, self.readyDeferred = self.readyDeferred, None
        d.callback(None)

    def _run(self, executable, args):
        def callback(result):
            deferred.callback(result)

        def errback(failure):
            try:
                failure.trap(_UnexpectedErrorOutput)
            except:
                deferred.errback(failure)
            else:
                failure.value.processEnded.addErrback(
                    lambda _: onProcessEnded(failure)
                ).addErrback(lambda f: deferred.errback(f))

        def onProcessEnded(failure):
            # _UnexpectedErrorOutput ???
            raise FFMPEGAdapterError(str(failure.value))

        deferred = Deferred()

        d = maybeDeferred(
            getProcessOutput, executable, args=args, reactor=self._reactor)

        d.addCallback(callback)
        d.addErrback(errback)

        return deferred


def decodeUint(value, length):
    if not value:
        return 0
    v = value[:length]
    if Constants.IS_LITTLE_ENDIAN:
        v = v[::-1]
    r = 0
    for i in range(length):
        r |= (v[i] << (i * 8))
    return r


def encodeUint(value, length):
    t = []
    for i in range(length):
        shiftLength = i if not Constants.IS_LITTLE_ENDIAN else length - (i + 1)
        t.append((value >> (shiftLength * 8)) & 0xFF)
    return bytes(t)


def buildJid(user, server, agent, device):
    if not server:
        raise ValueError("Server Required")
    if user is None:
        user = ""
    jid = user
    if agent:
        jid = jid + "_" + str(agent)
    if device:
        jid = jid + ":" + str(device)
    jid = jid + "@" + server
    return jid


_EMTPY_JID = (None, None, None, None)


def splitJid(jid):
    if not jid:
        raise ValueError("Empty Jid")

    try:
        u, server = jid.split("@")
    except ValueError:
        raise ValueError("Invalid jid format: %s" % (jid, ))

    try:
        userAgent, device = u.split(":")
    except ValueError:
        return (u, None, None, server)

    if device == "":
        device = None

    user, agent = _splitUserAgent(userAgent)

    if agent == "":
        agent = None

    return (user, agent, device, server)


def _splitUserAgent(userAgent):
    try:
        user, agent = userAgent.split("_")
    except ValueError:
        return (userAgent, None)

    return (user, agent)


def isJidSameUser(jid1, jid2):
    jid1User, _, _, jid1Server = splitJid(jid1)
    jid2User, _, _, jid2Server = splitJid(jid2)
    return jid1User == jid2User


def isGroupJid(jid):
    user, _, _, server = splitJid(jid)
    return "-" in user or server == "g.us"
