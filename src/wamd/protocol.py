import time
import base64
import os
import json

from io import BytesIO

from twisted.internet.defer import (
    inlineCallbacks,
    Deferred,
    maybeDeferred,
    succeed,
    fail
)
from twisted.protocols.tls import TLSMemoryBIOFactory
from twisted.internet.task import LoopingCall
from twisted.python.failure import Failure
from twisted.python.reflect import qual
from twisted.logger import Logger

from autobahn.twisted.websocket import WebSocketClientProtocol, WebSocketClientFactory
from autobahn.websocket.protocol import WebSocketProtocol

from dissononce.processing.impl.handshakestate import HandshakeState
from dissononce.processing.impl.cipherstate import CipherState
from dissononce.cipher.aesgcm import AESGCMCipher
from dissononce.dh.x25519.x25519 import X25519DH
from dissononce.hash.sha256 import SHA256Hash
from dissononce.processing.handshakepatterns.interactive.XX import XXHandshakePattern
from dissononce.dh.keypair import KeyPair as X25519KeyPair
from dissononce.dh.x25519.private import PrivateKey as X25519PrivateKey
from dissononce.dh.x25519.public import PublicKey as X25519PublicKey

from consonance.dissononce_extras.processing.symmetricstate_wa import WASymmetricState

from axolotl.ecc import curve, djbec
from axolotl.util.keyhelper import KeyHelper
from axolotl.state.prekeybundle import PreKeyBundle
from axolotl.identitykey import IdentityKey


from .constants import Constants
from .common import AuthState
from .errors import (
    ConnectionClosed,
    AuthenticationFailedError,
    StreamEndError,
    NodeStreamError,
    WAMDError
)
from .coder import WABinaryReader, WABinaryWriter, Node

from .utils import (
    encodeUint,
    decodeUint,
    splitJid,
    buildJid,
    isJidSameUser,
    isGroupJid,
    jidNormalize,
    generateRandomNumber,
    toCommaSeparatedNumber,
    inflate,
    sha256Hash,
    mimeTypeFromBuffer,
    mediaTypeFromMime,
    mediaTypeFromMessageProto,
    messageTypeFromProto,
    encryptMedia,
    processImage,
    addRandomPadding,
    FFMPEGVideoAdapter
)
from .handlers import createNodeHandler
from ._tls import getTlsConnectionFactory
from .proto import WAMessage_pb2
from .messages import (
    ContactMessage,
    ContactsArrayMessage,
    WhatsAppMessage,
    TextMessage,
    MediaMessage,
    ExtendedTextMessage,
    StickerMessage,
    LocationMessage,
    LiveLocationMessage,
    ListMessage
)
from .signalhelper import (
    processPreKeyBundle,
    encrypt as signalEncrypt,
    groupEncrypt,
    getOrCreateSenderKeyDistributionMessage
)
from .http import request as doHttpRequest
from .common import AuthState
from .iface import (
    ISignalStore,
    ICachedMediaStore,
    IGroupStore,
    IMessageStore
)
from .conn_utils import getUsyncDeviceList


_VALID_EVENTS = ["qr", "close", "inbox", "receipt"]


class MultiDeviceWhatsAppClient(WebSocketClientProtocol):

    log = Logger() # set your own logger instance

    # noise protocol
    _noiseHandshakeState = None
    _recvCipher = None
    _sendCipher = None

    _serverHelloDeferred = None

    def __init__(self, authState=None, useSentQueue=False, reactor=None):
        WebSocketClientProtocol.__init__(self)

        validEvents = [] if self._valid_events is None else self._valid_events.copy()
        validEvents.extend(_VALID_EVENTS)

        self.set_valid_events(validEvents)

        if authState is None:
            authState = AuthState()

        self.authState = authState

        if reactor is None:
            from twisted.internet import reactor

        self.reactor = reactor
        self._pendingRequest = {}

    def onOpen(self):
        self.log.info("Connected to whatsapp server: {peer}", peer=self.transport.getPeer())
        self.factory._onOpen(self)

    def onClose(self, wasClean, code, reason):
        self.log.info("Connection Closed: wasClean: {wasClean}, code: {code}, reason: {reason}",
            wasClean=wasClean, code=code, reason=reason)

        if self._keepAliveLoop is not None:
            try:
                self._keepAliveLoop.stop()
            except:
                pass
            self._keepAliveLoop = None

        if self._failure is not None:
            failure, self._failure = self._failure, None
        else:
            failure = None

        # do not fire "close" event when restarting connection
        # after authentication success.

        if not self._authDone():
            self._stopQrLoop()

            if self.factory.readyDeferred is not None:
                self.factory._onClose(self)
            else:
                if self.factory._authState is None:
                    if failure is None:
                        failure = AuthenticationFailedError("Connection is closed during authentication")
                    self.factory.authFailure(failure)
        else:
            if failure is not None and isinstance(failure.value, NodeStreamError):
                if failure.value.code == "401":
                    excReason = ConnectionClosed(isLoggedOut=True, reason="Connection Closed Cleanly (Logged Out)")
                else:
                    excReason = ConnectionClosed(reason="Unhandled Stream Error, Code: %s" % (failure.value))
            else:
                excReason = ConnectionClosed(reason="Connection Closed Cleanly")

            self.fire("close", self, Failure(excReason))

    def _authDone(self):
        return self.factory.authDeferred is None

    def onMessage(self, message, isBinary):
        self.log.debug("OnMessage Received [{message}]\n", message=toCommaSeparatedNumber(message))

        # TODO
        # Handle close message (b'\x88\x02\x03\xf3')

        if self._serverHelloDeferred is not None:
            handshakeMsg = WAMessage_pb2.HandshakeMessage()
            handshakeMsg.ParseFromString(message[3:])
            serverHello = handshakeMsg.serverHello
            d, self._serverHelloDeferred = self._serverHelloDeferred, None
            d.callback(serverHello)
        else:
            while message:
                messageLength = decodeUint(message[:3], 3)
                encrypted = message[3:messageLength + 3]
                message = message[messageLength + 3:]

                self.log.debug("OnMessage, Encrypted: [{encrypted}]\n", encrypted=toCommaSeparatedNumber(encrypted))

                if self._recvCipher is not None:
                    try:
                        decrypted = self._recvCipher.decrypt_with_ad(b"", encrypted)
                    except:
                        self.log.failure("Noise Decrypt Failed")
                    else:
                        self.log.debug("OnMessage, Decrypted: [{decrypted}]\n", decrypted=toCommaSeparatedNumber(decrypted))

                        try:
                            if decrypted[0] & Constants.FLAG_COMPRESSED:
                                decrypted = inflate(decrypted[1:])
                            else:
                                decrypted = decrypted[1:]
                            node = WABinaryReader(decrypted).readNode()
                        except StreamEndError:
                            self._streamEndReceived = True
                            self._clearTransportCipher()
                        else:
                            self.messageNodeReceived(node)


    def authenticate(self):
        d = self._doHandshake()
        d.addErrback(self._handleFailure)
        deferred = self.factory.authDeferred
        return deferred

    _failure = None

    def _handleFailure(self, failure):
        if isinstance(failure, Exception):
            failure = Failure(failure)

        self.log.failure("Handle Failure", failure=failure)

        if not self._authDone() or isinstance(failure.value, NodeStreamError):
            self._failure = failure

        if isinstance(failure.value, AuthenticationFailedError):
            # The server does not send xmlstreamend after sending
            # failure node. (<failure reason="401" location="vll"></failure>)
            self._clearTransportCipher()

    def _clearTransportCipher(self):
        # For now, this should be called before closing the connection
        # Or after receiving closing signal from server.
        # To prevent InvalidTag exception when decrypting
        # close message. (b'\x88\x02\x03\xf3')
        self._sendCipher = None
        self._recvCipher = None

    @inlineCallbacks
    def _doHandshake(self):
        serverHello = yield self._waitServerHello()

        self.log.debug("ServerHello: {serverHello}", serverHello=serverHello)

        messageBuffer = bytearray()

        self._noiseHandshakeState.read_message(
            serverHello.ephemeral + serverHello.static + serverHello.payload,
            messageBuffer)

        cert = WAMessage_pb2.NoiseCertificate()
        cert.ParseFromString(bytes(messageBuffer))
        certDetails = WAMessage_pb2.Details()
        certDetails.ParseFromString(cert.details)

        if certDetails.issuer != Constants.CERTIFICATE_ISSUER:
            raise AuthenticationFailedError("Noise certificate issued by unknown source: %s" % (certDetails.issuer))

        if not curve.Curve.verifySignature(
            djbec.DjbECPublicKey(Constants.WHATSAPP_LONG_TERM),
            cert.details,
            cert.signature
        ):
            raise AuthenticationFailedError("Invalid signature on noise ceritificate")

        if certDetails.key != self._noiseHandshakeState.rs.data:
            raise AuthenticationFailedError("Noise certificate key does not match proposed server static key")

        if certDetails.HasField("expires") and certDetails.expires < int(time.time()):
            raise AuthenticationFailedError("Noise certificate expired")

        self.log.debug("Certificate Verifcation OK")

        clientPayload = yield self._buildClientPayloadHandshake()

        self.log.debug("Client Payload: {clientPayload}", clientPayload=clientPayload)

        messageBuffer = bytearray()

        cipherPair = self._noiseHandshakeState.write_message(
            clientPayload.SerializeToString(),
            messageBuffer)

        self._sendCipher, self._recvCipher = cipherPair

        clientFinish = WAMessage_pb2.ClientFinish(
            static=bytes(messageBuffer[:48]),
            payload=bytes(messageBuffer[48:]))

        handshakeMsg = WAMessage_pb2.HandshakeMessage()
        handshakeMsg.clientFinish.MergeFrom(clientFinish)

        self.log.debug("Client Finish: {clientFinish}", clientFinish=handshakeMsg)

        clientFinishMessage = handshakeMsg.SerializeToString()
        clientFinishPayload = encodeUint(len(clientFinishMessage), 3) + clientFinishMessage

        self.sendMessage(clientFinishPayload, isBinary=True)

        self._startKeepAliveLoop()


    @inlineCallbacks
    def _waitServerHello(self):
        yield self._sendClientHello()
        self._serverHelloDeferred = Deferred()
        return (yield self._serverHelloDeferred)

    @inlineCallbacks
    def _sendClientHello(self):
        yield self.authState.initKeys()
        # Noise Initialization Noise_XX_25519_AESGCM_SHA256
        # ('e',),
        # ('e', 'ee', 's', 'es'),
        # ('s', 'se')

        self._noiseHandshakeState = HandshakeState(
            WASymmetricState(
                CipherState(
                    AESGCMCipher()
                ),
                SHA256Hash()
            ),
            X25519DH())

        self._noiseHandshakeState.initialize(
            XXHandshakePattern(),
            True,
            Constants.PROLOGUE,
            s=X25519KeyPair(
                X25519PublicKey(self.authState.noiseKey.getPublicKey().getPublicKey()),
                X25519PrivateKey(self.authState.noiseKey.getPrivateKey().getPrivateKey())
            ))

        ephemeralPublic = bytearray()
        self._noiseHandshakeState.write_message(b"", ephemeralPublic)

        clientHello = WAMessage_pb2.ClientHello()
        clientHello.ephemeral = bytes(ephemeralPublic)

        handshakeMsg = WAMessage_pb2.HandshakeMessage(clientHello=clientHello)

        self.log.debug("ClientHello: {handshakeMsg}", handshakeMsg=handshakeMsg)

        clientHelloMsg = handshakeMsg.SerializeToString()
        clientHelloPayload = bytes(Constants.PROLOGUE) + encodeUint(len(clientHelloMsg), 3) + clientHelloMsg

        self.sendMessage(clientHelloPayload, True)

    @inlineCallbacks
    def _buildClientPayloadHandshake(self):
        browser = Constants.DEFAULT_BROWSER_KIND
        version = Constants.WHATSAPP_WEB_VERSION

        clientPayload = WAMessage_pb2.ClientPayload()

        clientPayload.connectReason = 1
        clientPayload.connectType = 1

        if not self.authState.has("me"):
            clientPayload.passive = False

            companionRegData = WAMessage_pb2.CompanionRegData()
            companionRegData.buildHash = base64.b64decode(Constants.BUILD_HASH)

            companionProps = WAMessage_pb2.CompanionProps()
            companionProps.os = browser[0]

            appVersion = WAMessage_pb2.AppVersion()
            appVersion.primary = 10
            companionProps.version.MergeFrom(appVersion)
            companionProps.platformType = 1
            companionProps.requireFullSync = False

            signalStore = ISignalStore(self.authState)

            identityKeyPair = yield maybeDeferred(signalStore.getIdentityKeyPair)
            registrationId = yield maybeDeferred(signalStore.getLocalRegistrationId)
            signedPreKey = yield maybeDeferred(signalStore.loadSignedPreKey, -1)

            companionRegData.companionProps = companionProps.SerializeToString()
            companionRegData.eRegid = encodeUint(registrationId, 4)
            companionRegData.eKeytype = encodeUint(5, 1)
            companionRegData.eIdent = identityKeyPair.getPublicKey().getPublicKey().getPublicKey()
            companionRegData.eSkeyId = encodeUint(signedPreKey.getId(), 3)
            companionRegData.eSkeyVal = signedPreKey.getKeyPair().getPublicKey().getPublicKey()
            companionRegData.eSkeySig = signedPreKey.getSignature()

            clientPayload.regData.MergeFrom(companionRegData)
        else:
            self.log.debug("Auth State: {authState}", authState=self.authState)
            clientPayload.passive = True
            user, agent, device, server = splitJid(self.authState.me['jid'])
            clientPayload.username = int(user)
            clientPayload.device = int(device)

        userAgentAppVersion = WAMessage_pb2.AppVersion()
        userAgentAppVersion.primary = version[0]
        userAgentAppVersion.secondary = version[1]
        userAgentAppVersion.tertiary = version[2]

        userAgent = WAMessage_pb2.UserAgent()
        userAgent.appVersion.MergeFrom(userAgentAppVersion)
        userAgent.platform = WAMessage_pb2.UserAgent.WEB
        userAgent.releaseChannel = 0
        userAgent.mcc = "000"
        userAgent.mnc = "000"
        userAgent.osVersion = browser[2]
        userAgent.manufacturer = ""
        userAgent.device = browser[1]
        userAgent.osBuildNumber = "0.1"
        userAgent.localeLanguageIso6391 = "en"
        userAgent.localeCountryIso31661Alpha2 = "en"

        clientPayload.userAgent.MergeFrom(userAgent)

        webInfo = WAMessage_pb2.WebInfo()
        webInfo.webSubPlatform = 0

        clientPayload.webInfo.MergeFrom(webInfo)
        return clientPayload

    @inlineCallbacks
    def messageNodeReceived(self, node):
        self.log.debug("Node Received:\n\n{node}\n", node=node)

        nodeHandler = None

        try:
            nodeHandler = createNodeHandler(node.tag, self.reactor)
        except:
            # TODO
            # handle failure when login
            self._handleFailure(Failure())

        if not nodeHandler:
            return

        self.log.debug("Using {handler} to handle [{tag}] node", handler=nodeHandler, tag=node.tag)

        try:
            yield maybeDeferred(nodeHandler.handleNode, self, node)
        except:
            # TODO
            # handle failure when login
            self._handleFailure(Failure())


    _streamEndReceived = False

    @property
    def isClosingOrClosed(self):
        return (
            self.state == WebSocketProtocol.STATE_CLOSING or
            self.state == WebSocketProtocol.STATE_CLOSED or
            self._streamEndReceived)

    def sendMessageNode(self, node):
        if self.isClosingOrClosed:
            raise WAMDError("Websocket is closing or closed")

        self.log.debug("Message Node:\n\n{node}\n", node=node)

        encoded = b"\x00" + WABinaryWriter(node).getData()
        self.log.debug("Message Node Encoded: [{encoded}]\n", encoded=toCommaSeparatedNumber(encoded))

        encrypted = self._sendCipher.encrypt_with_ad(b"", encoded)
        self.log.debug("Message Node Encrypted: [{encrypted}]\n", encrypted=toCommaSeparatedNumber(encrypted))

        payload = encodeUint(len(encrypted), 3) + encrypted
        self.log.debug("Message Payload: [{payload}]\n", payload=toCommaSeparatedNumber(payload))

        self.sendMessage(payload, isBinary=True)

    def request(self, node):
        deferred = Deferred()
        try:
            self.sendMessageNode(node)
        except:
            deferred.errback(Failure())
        else:
            self._pendingRequest[node['id']] = deferred
        return deferred

    def sendReadReceipt(self, message):
        if message['fromMe'] or isJidSameUser(message['from'], self.authState.me['jid']):
            return fail(WAMDError("Cannot Send Read Receipt To Our Own Device"))

        receiptNode = Node("receipt", {
            'to': jidNormalize(message['from']),
            'type': "read",
            'id': message['id'],
            't': str(int(time.time()))
        })

        if message['participant'] is not None:
            receiptNode['participant'] = message['participant']

        return self.request(receiptNode)

    def disconnectFromServer(self, logout=False):
        if logout:
            self._sendLogout()
            self._handleFailure(NodeStreamError("401"))

        # self.reactor.callLater(0, lambda: self.sendClose(code=1000))
        # want to use self.sendClose, but it seems that the server
        # is the only one who can close the connection.
        self._sendStreamEnd()

    def _sendLogOut(self):
        self.sendMessageNode(Node(
            "iq", {
                'to': Constants.S_WHATSAPP_NET,
                'type': "set",
                'id': self._generateMessageId(),
                'xmlns': "md"
            }, Node("remove-companion-device", {
                'jid': self.authState.me['jid'],
                'reason': "user_initiated"
            })
        ))

    def sendMsg(self, message):
        # TODO
        # Implement queue/locking.
        # So that only one message can be sent at a time.
        if not isinstance(message, WhatsAppMessage):
            return fail(
                TypeError("Must be an instance of %s" % qual(WhatsAppMessage))
            )

        if isinstance(message, TextMessage):
            d = self._processTextMessage(message)

        elif isinstance(message, ExtendedTextMessage):
            d = self._processExtendedTextMessage(message)

        elif isinstance(message, MediaMessage):
            d = self._processMediaMessage(message)

        elif isinstance(message, StickerMessage):
            d = self._processMediaMessage(message)

        elif isinstance(message, ContactMessage):
            d = self._processContactMessage(message)

        elif isinstance(message, (LocationMessage, LiveLocationMessage)):
            d = self._processLocationMessage(message)

        elif isinstance(message, ListMessage):
            d = self._processListMessage(message)

        elif isinstance(message, ContactsArrayMessage):
            d = self._processContactsArrayMessage(message)

        else:
            return fail(
                NotImplementedError("%s is not implemented" % qual(message.__class__))
            )

        # TODO
        # Before sending to group, maybe check if group exists

        messageStore = IMessageStore(self.authState)
        messageStored = [False]

        @inlineCallbacks
        def onProcessMessageDone(messageNode):
            webMessageInfoProto = WAMessage_pb2.WebMessageInfo()
            messageKey = WAMessage_pb2.MessageKey()
            messageKey.remoteJid = message['to']
            messageKey.fromMe = True
            messageKey.id = message['id']

            webMessageInfoProto.key.MergeFrom(messageKey)
            webMessageInfoProto.message.MergeFrom(message.toProtobufMessage())

            yield messageStore.storeMessage(message['id'], webMessageInfoProto)

            messageStored[0] = True

            responseAck = yield self.request(messageNode)

            @inlineCallbacks
            def _maybeFlagSenderKeys():
                participants = messageNode.findChild("participants")
                if not participants:
                    return
                groupStore = IGroupStore(self.authState)
                groupId = message['to'].split("@")[0]
                try:
                    for toNode in participants.findChilds("to"):
                        yield maybeDeferred(groupStore.flagSenderKey, groupId, toNode['jid'])
                except:
                    pass

            if isGroupJid(message['to']):
                self.reactor.callLater(0, _maybeFlagSenderKeys)

            return message

        @inlineCallbacks
        def errback(f):
            if messageStored[0]:
                yield messageStore.removeMessage(
                    "%s%s" % (Constants.MESSAGE_STORE_RETRY_PREFIX, message['id']))
            return f

        return d.addCallback(onProcessMessageDone).addErrback(errback)

    # sendMessage used by WebSocketClientProtocol
    relayMessage = sendMsg

    def _processTextMessage(self, message):
        if not message['conversation']:
            return fail(ValueError("conversation parameters required"))
        return self._makeMessageNode(message, "text")

    def _processExtendedTextMessage(self, message):
        if not message['text']:
            return fail(ValueError("text parameters required"))
        message["jpegThumbnail"] = None if not message._attrs.get("thumbnail") else self._opts(message._attrs, "thumbnail")
        return self._makeMessageNode(message, "text")

    def _processLocationMessage(self, message):
        if (not message["degreesLatitude"]) and (not message["degreesLongitude"]):
            return fail(ValueError("degreesLatitude and degreesLongitude parameters required"))
        message["jpegThumbnail"] = None if not message._attrs.get("thumbnail") else self._opts(message._attrs, "thumbnail")
        return self._makeMessageNode(message, "media", "location" if isinstance(message, LocationMessage) else "livelocation")

    def _processListMessage(self, message):
        if (not message["sections"]) and (not message["buttonText"]) and (not message["description"]):
            return fail(ValueError("description, buttonText, and sections parameters required"))
        message["listType"] = 1 if not message["listType"] else message["listType"]
        return self._makeMessageNode(message, "media", "list")

    @inlineCallbacks
    def _processMediaMessage(self, message):
        if isinstance(message['url'], bytes):
            fileContent = message['url']
        elif isinstance(message['url'], BytesIO):
            fileContent = message['url'].getvalue()
        elif message['url'].startswith("http:") or message['url'].startswith("https:"):
            self.log.debug("Downloading file from {url}", url=message['url'])
            try:
                fileContent = yield doHttpRequest(message['url'])
            except:
                raise WAMDError("Failed to download media from %s\n%s" % (message['url'], Failure()))
        else:
            if not os.path.exists(message['url']):
                raise FileNotFoundError("File %s not found" % (message['url']))

            fileIO = open(message['url'], "rb")
            fileContent = fileIO.read()
            fileIO.close()

        fileSha256 = sha256Hash(fileContent)

        cachedMediaStore = ICachedMediaStore(self.authState)
        savedMedia = yield maybeDeferred(cachedMediaStore.getCachedMedia, fileSha256)

        if savedMedia is None:
            mediaData = {}

            if message['mimetype'] is not None:
                mimeType = message['mimetype']
            else:
                mimeType = mimeTypeFromBuffer(fileContent)

            mediaType = mediaTypeFromMime(mimeType)

            encryptResult = encryptMedia(fileContent, mediaType)

            mediaData['mimetype'] = mimeType
            mediaData['fileSha256'] = base64.b64encode(fileSha256).decode()
            mediaData['fileLength'] = len(fileContent) if not message._attrs.get("fileLength") else message._attrs.get("fileLength")
            mediaData['mediaKey'] = base64.b64encode(encryptResult['mediaKey']).decode()
            mediaData['fileEncSha256'] = base64.b64encode(encryptResult['fileEncSha256']).decode()
            mediaData['mediaKeyTimestamp'] = encryptResult['mediaKeyTimestamp']

            if mimeType == "image/webp":
                yield maybeDeferred(self._addStickerInfo, message, fileContent, mediaData)

            elif mediaType == "image":
                yield maybeDeferred(self._addImageInfo, message, fileContent, mediaData)

            elif mediaType == "document":
                yield maybeDeferred(self._addDocumentInfo, message, fileContent, mediaData)

            elif mediaType == "video":
                yield maybeDeferred(self._addVideoInfo, message, fileContent, mediaData)

            elif mediaType == "audio":
                yield maybeDeferred(self._addAudioInfo, message, fileContent, mediaData)

            uploadToken = base64.urlsafe_b64encode(encryptResult['fileEncSha256']).decode()

            # Upload media
            yield self._addUploadInfo(
                uploadToken,
                encryptResult['enc'] + encryptResult['mac'],
                mediaData)

            yield maybeDeferred(
                cachedMediaStore.saveCachedMedia,
                fileSha256,
                {'mediaType': mediaType, 'mediaData': mediaData})
        else:
            self.log.debug("Sending Media Using Cached Data {savedMedia}", savedMedia=savedMedia)
            mediaType = savedMedia['mediaType']
            mediaData = savedMedia['mediaData']
            if message._attrs.get("fileLength"):
                mediaData['fileLength'] = message._attrs.get("fileLength")

        message['mediaType'] = mediaType

        for k, v in mediaData.items():
            message[k] = v

        return (yield self._makeMessageNode(message, "media", mediaType))

    def _processContactMessage(self, message):
        if message['vcard']:
            return self._makeMessageNode(message, "text")
        return fail(ValueError('vcard parameters required'))

    def _processContactsArrayMessage(self, message):
        if not message['contacts']:
            return fail(ValueError('contacts parameters required'))
        return self._makeMessageNode(message, "text")
    @inlineCallbacks
    def _addUploadInfo(self, uploadToken, body, mediaData):
        mediaConnInfo = yield self.request(Node(
            "iq", {
                'to': Constants.S_WHATSAPP_NET,
                'xmlns': "w:m",
                'type': "set",
                'id': self._generateMessageId()
            }, Node("media_conn")
        ))

        mediaConn = mediaConnInfo.findChild("media_conn")
        hostList = mediaConn.findChilds("host")

        uploadUrl = "https://{hostName}/mms/image/{uploadToken}".format(
            hostName=hostList[0]['hostname'],
            uploadToken=uploadToken)

        uploadResult = yield doHttpRequest(
            uploadUrl,
            method="POST",
            data=body,
            query={
                'auth': mediaConn['auth'],
                'token': uploadToken
            },
            headers={
                'Origin': Constants.WHATSAPP_WEBSOCKET_HOST.rstrip("/"),
                'Referer': Constants.WHATSAPP_WEBSOCKET_HOST.rstrip("/") + "/",
                'User-Agent': Constants.DEFAULT_USER_AGENT
            })

        uploadResultDict = json.loads(uploadResult)

        mediaData['url'] = uploadResultDict['url']
        mediaData['directPath'] = uploadResultDict['direct_path']

    def _opts(self, message, type):
        if type == "thumbnail":
            out = message.get("thumbnail")
            if isinstance(out, bytes):
                return out.decode()
            else:
                return out

    def _addImageInfo(self, message, imageBytes, mediaData):
        height, width, thumbnail = processImage(imageBytes, mediaData['mimetype'])
        mediaData['height'] = height
        mediaData['width'] = width
        mediaData['jpegThumbnail'] = base64.b64encode(thumbnail).decode() if not message._attrs.get("thumbnail") else self._opts(message._attrs, "thumbnail")

    def _addDocumentInfo(self, message, documentBytes, mediaData):
        pathSplit = os.path.splitext(message['url'])

        if message['title'] is None:
            mediaData['title'] = pathSplit[0].split("/")[-1]
        else:
            mediaData = message['title']

        if message['fileName'] is None:
            if not pathSplit[1]:
                fileName = pathSplit[0].split("/")[-1]
            else:
                fileName = "%s%s" % (pathSplit[0].split("/")[-1], pathSplit[1])
            mediaData['fileName'] = fileName
        else:
            mediaData['fileName'] = message['fileName']

    @inlineCallbacks
    def _addVideoInfo(self, message, videoBytes, mediaData):
        adapter = FFMPEGVideoAdapter.fromBytes(videoBytes)
        yield adapter.ready()
        duration = int(adapter.info['format']['duration'])
        frameIO = BytesIO()
        yield adapter.saveFrame(frameIO, int(duration // 2))
        _, _, jpegThumbnail = processImage(frameIO.getvalue(), "image/jpeg")
        frameIO.close()
        mediaData['seconds'] = duration if not message._attrs.get("duration") else message._attrs.get("duration")
        mediaData['jpegThumbnail'] = base64.b64encode(jpegThumbnail).decode() if not message._attrs.get("thumbnail") else self._opts(message._attrs, "thumbnail")
 
    @inlineCallbacks
    def _addAudioInfo(self, message, audioBytes, mediaData):
        if mediaData['mimetype'] == "application/ogg":
            mediaData['mimetype'] = "audio/ogg; codecs=opus"
            mediaData['ptt'] = True
        adapter = FFMPEGVideoAdapter.fromBytes(audioBytes)
        yield adapter.ready()
        os.remove(adapter.info['format']['filename'])
        duration = int(adapter.info['format']['duration'])
        mediaData['ptt'] = mediaData.get("ptt", False) if not message._attrs.get("ptt") else message._attrs.get("ptt")
        mediaData['seconds'] = duration if not message._attrs.get("duration") else message._attrs.get("duration")

    def _addStickerInfo(self, message, stickerBytes, mediaData):
        mediaData["isAnimated"] = message._attrs.get("isAnimated", False)

    def _usyncQuery(self, jids, context):
        if not jids:
            return fail(ValueError("jids required in usync query"))

        iqNode = Node("iq", {
            'to': Constants.S_WHATSAPP_NET,
            'xmlns': "usync",
            'type': "get",
            'id': self._generateMessageId()
        }, Node("usync", {
            'sid': self._generateMessageId(),
            'index': "0",
            'last': "true",
            'mode': "query",
            'context': context
        }, [
            Node("query", None, Node("devices", {'version': '2'})),
            Node("list", None, [Node("user", {'jid': jid}) for jid in jids])
        ]))

        return self.request(iqNode)

    @inlineCallbacks
    def _makeMessageNode(self, message, messageType, mediaType=None, retryCount=None):
        isGroup = isGroupJid(message['to'])

        messageNode = Node("message", {
            'id': message['id'],
            'to': message['to'],
            'type': messageType
        })

        messageProto = message.toProtobufMessage()

        signalStore = ISignalStore(self.authState)

        @inlineCallbacks
        def _ensureE2ESession(recipients):
            if not recipients:
                return
            keyRequestJids = []
            for recipient in recipients:
                if not (yield maybeDeferred(
                    signalStore.containSession, recipient.split("@")[0], 1)
                ):
                    keyRequestJids.append(recipient)

            if keyRequestJids:
                preKeyBundles = yield self._requestPreKeyBundles(keyRequestJids)
                for fullJid, preKeyBundle in preKeyBundles.items():
                    yield processPreKeyBundle(signalStore, preKeyBundle, fullJid.split("@")[0])

        @inlineCallbacks
        def _getUsyncRecipients(usyncJids):
            userDevices = getUsyncDeviceList((yield self._usyncQuery(usyncJids, "message")).findChild("usync"))
            userDevices[meJid].remove(meDevice)
            recipients = []
            for p, devices in userDevices.items():
                user, agent, _, server = splitJid(p)
                for device in devices:
                    if device == "0":
                        recipients.append(p)
                    else:
                        recipients.append(buildJid(user, server, agent, device))
            return recipients

        meUser, meAgent, meDevice, meServer = splitJid(self.authState.me['jid'])
        meJid = jidNormalize(self.authState.me['jid'])

        if isGroup:
            groupId = message['to'].split("@")[0]
            groupStore = IGroupStore(self.authState)
            participants = yield maybeDeferred(
                groupStore.getAllGroupParticipants, groupId)

            usyncJids = [p['jid'] for p in participants]
            deviceParticipants = yield _getUsyncRecipients(usyncJids)

            flaggedSenderKeys = yield maybeDeferred(
                groupStore.getAllFlaggedSenderKeys, groupId)

            recipients = []

            for p in flaggedSenderKeys:
                if p not in deviceParticipants:
                    yield maybeDeferred(groupStore.removeSenderKeyFlag, groupId, p)

            for p in deviceParticipants:
                if p not in flaggedSenderKeys:
                    recipients.append(p)

        else:
            usyncJids = [message['to'], jidNormalize(self.authState.me['jid'])]
            recipients = yield _getUsyncRecipients(usyncJids)

        participantsNode = None
        skMsgNode = None

        yield _ensureE2ESession(recipients)

        if isGroup:
            participantId = self.authState.me['jid'].split("@")[0]
            if recipients:
                skMessage = yield getOrCreateSenderKeyDistributionMessage(
                    signalStore, groupId, participantId)

                skMessageProto = WAMessage_pb2.SenderKeyDistributionMessage()
                skMessageProto.groupId = message['to']
                skMessageProto.axolotlSenderKeyDistributionMessage = skMessage.serialize()

                senderKeyMessageProto = WAMessage_pb2.Message()
                senderKeyMessageProto.senderKeyDistributionMessage.MergeFrom(skMessageProto)

                participantsNode = Node("participants")

                for recipient in recipients:
                    type, cipherText = yield signalEncrypt(
                        signalStore,
                        addRandomPadding(senderKeyMessageProto.SerializeToString()),
                        recipient.split("@")[0])

                    participantsNode.addChild(Node(
                        "to", {
                            'jid': recipient
                        }, Node("enc", {
                            'v': "2",
                            'type': type
                        }, cipherText)
                    ))

            groupCipherText = yield groupEncrypt(
                signalStore, groupId, participantId,
                addRandomPadding(messageProto.SerializeToString()))

            skMsgNode = Node("enc", {
                'v': "2",
                'type': "skmsg"
            }, groupCipherText)

            if mediaType is not None:
                skMsgNode['mediatype'] = mediaType

        else:
            deviceSentMessageProto = WAMessage_pb2.DeviceSentMessage()
            deviceSentMessageProto.destinationJid = message['to']
            deviceSentMessageProto.message.MergeFrom(messageProto)
            deviceMessageProto = WAMessage_pb2.Message()
            deviceMessageProto.deviceSentMessage.MergeFrom(deviceSentMessageProto)

            participantsNode = Node("participants")

            for recipient in recipients:
                if isJidSameUser(recipient, self.authState.me['jid']):
                    paddedMessage = addRandomPadding(deviceMessageProto.SerializeToString())
                else:
                    paddedMessage = addRandomPadding(messageProto.SerializeToString())
                type, cipherText = yield signalEncrypt(signalStore,
                    paddedMessage, recipient.split("@")[0])

                encNode = Node("enc", {
                    'v': "2",
                    'type': type
                }, cipherText)

                if mediaType is not None:
                    encNode['mediatype'] = mediaType

                participantsNode.addChild(Node(
                    "to", {
                        'jid': recipient
                    }, encNode
                ))

        hasPkMsg = False
        if participantsNode is not None:
            messageNode.addChild(participantsNode)
            hasPkMsg = list(filter(
                lambda toNode: toNode.getChild("enc")['type'] == "pkmsg",
                participantsNode.findChilds("to"))).__len__() > 0

        if skMsgNode is not None:
            messageNode.addChild(skMsgNode)

        if hasPkMsg:
            messageNode.addChild(self._buildDeviceIdentityNode())

        return messageNode


    @inlineCallbacks
    def _makeRetryMessageNode(self, webMessageInfoProto, retryCount):
        messageProto = webMessageInfoProto.message
        messageType = messageTypeFromProto(messageProto)

        if webMessageInfoProto.key.participant:
            recipientId = webMessageInfoProto.key.participant.split("@")[0]

            skMessage = yield getOrCreateSenderKeyDistributionMessage(
                ISignalStore(self.authState),
                webMessageInfoProto.key.remoteJid.split("@")[0],
                self.authState.me['jid'].split("@")[0])

            skMessageProto = WAMessage_pb2.SenderKeyDistributionMessage()
            skMessageProto.groupId = webMessageInfoProto.key.remoteJid
            skMessageProto.axolotlSenderKeyDistributionMessage = skMessage.serialize()

            messageProto.senderKeyDistributionMessage.MergeFrom(skMessageProto)

        else:
            recipientId = webMessageInfoProto.key.remoteJid.split("@")[0]

        type, cipherText = yield signalEncrypt(
            ISignalStore(self.authState),
            addRandomPadding(messageProto.SerializeToString()),
            recipientId)

        encNode = Node("enc", {
            'v': "2",
            'type': type,
            'count': str(retryCount)
        }, cipherText)

        if messageType == "media":
            mediaType = mediaTypeFromMessageProto(messageProto)
            encNode['mediatype'] = mediaType

        messageNode = Node("message", {
            'id': webMessageInfoProto.key.id,
            'to': webMessageInfoProto.key.remoteJid,
            'type': messageType
        }, encNode)

        if webMessageInfoProto.key.participant:
            messageNode['participant'] = webMessageInfoProto.key.participant

        if encNode['type'] == "pkmsg":
            messageNode.addChild(self._buildDeviceIdentityNode())

        return messageNode


    @inlineCallbacks
    def _requestPreKeyBundles(self, jids):
        if not isinstance(jids, list):
            jids = [jids]

        iqNode = Node("iq", {
            'id': self._generateMessageId(),
            'xmlns': "encrypt",
            'type': "get",
            'to': "@c.us"
        })

        keyNode = Node("key")

        for jid in jids:
            keyNode.addChild(Node("user", {'jid': jid}))

        iqNode.addChild(keyNode)

        resultNode = yield self.request(iqNode)

        preKeyBundles = {}

        for userNode in resultNode.findChild("list").findChilds("user"):
            signedPreKeyNode = userNode.findChild("skey")
            preKeyNode = userNode.findChild("key")

            registrationId = decodeUint(userNode.findChild("registration").content, 4)
            identityKey = IdentityKey(djbec.DjbECPublicKey(userNode.findChild("identity").content))
            signedPreKeyId = decodeUint(signedPreKeyNode.findChild("id").content, 3)
            signedPreKeyPublic = djbec.DjbECPublicKey(signedPreKeyNode.findChild("value").content)
            signedPreKeySignature = signedPreKeyNode.findChild("signature").content

            if preKeyNode is None:
                preKeyId = None
                preKeyPublic = None
            else:
                preKeyId = decodeUint(preKeyNode.findChild("id").getContent(), 3)
                preKeyPublic = djbec.DjbECPublicKey(preKeyNode.findChild("value").content)

            preKeyBundles[userNode['jid']] = PreKeyBundle(
                registrationId, 1, preKeyId, preKeyPublic,
                signedPreKeyId, signedPreKeyPublic, signedPreKeySignature,
                identityKey)

        return preKeyBundles


    def _buildDeviceIdentityNode(self):
        deviceIdentityProto = WAMessage_pb2.ADVSignedDeviceIdentity()

        deviceIdentityProto.details = self.authState.signedDeviceIdentity['details']
        deviceIdentityProto.accountSignature = self.authState.signedDeviceIdentity['accountSignature']
        deviceIdentityProto.accountSignatureKey = self.authState.signedDeviceIdentity['accountSignatureKey']
        deviceIdentityProto.deviceSignature = self.authState.signedDeviceIdentity['deviceSignature']

        return Node(
            "device-identity",
            None,
            deviceIdentityProto.SerializeToString())

    @inlineCallbacks
    def _uploadPreKeys(self, count=None):
        nextPreKeyId = self.authState.nextPreKeyId

        self.log.debug("Uploading Prekeys")

        if count is None:
            count = Constants.MAX_PREKEYS_UPLOAD # whatsapp web send 30

        preKeys = KeyHelper.generatePreKeys(nextPreKeyId, count)
        maxPreKeyId = max([key.getId() for key in preKeys])

        preKeysContent = []

        signalStore = ISignalStore(self.authState)

        for preKey in preKeys:
            try:
                yield maybeDeferred(
                    signalStore.storePreKey, preKey.getId(), preKey)
                preKeysContent.append(
                    Node("key", None, [
                        Node("id", None, encodeUint(preKey.getId(), 3)),
                        Node("value", None, preKey.getKeyPair().getPublicKey().getPublicKey())
                    ]))
            except:
                self.log.error("Failed to store prekey: {failure}", failure=Failure())

        identityKeyPair = yield maybeDeferred(signalStore.getIdentityKeyPair)
        registrationId = yield maybeDeferred(signalStore.getLocalRegistrationId)
        signedPreKey = yield maybeDeferred(signalStore.loadSignedPreKey, -1)

        yield self.request(
            Node("iq", attributes={
                'id': self._generateMessageId(),
                'xmlns': "encrypt",
                'type': "set",
                'to': Constants.S_WHATSAPP_NET
            }, content=[
                Node("registration", None, encodeUint(registrationId, 4)),
                Node("type", None, encodeUint(curve.Curve.DJB_TYPE, 1)),
                Node("identity", None, identityKeyPair.getPublicKey().getPublicKey().getPublicKey()),
                Node("list", None, preKeysContent),
                Node("skey", None, [
                    Node("id", None, encodeUint(signedPreKey.getId(), 3)),
                    Node("value", None, signedPreKey.getKeyPair().getPublicKey().getPublicKey()),
                    Node("signature", None, signedPreKey.getSignature())
                ])
            ]))

        self.authState['nextPreKeyId'] = maxPreKeyId + 1

    @inlineCallbacks
    def _sendRetryReceiptRequest(self, messageNode):
        retryCount = messageNode.findChild("enc")['count']

        if retryCount is not None:
            retryCount = int(retryCount) + 1
        else:
            retryCount = 1

        receiptNode = Node("receipt", {
            'id': messageNode['id'],
            'to': messageNode['from'],
            'type': "retry"
        })

        if messageNode['participant'] is not None:
            receiptNode['participant'] = messageNode['participant']

        receiptNode.addChild(Node(
            "retry", {
                'v': "1",
                'count': str(retryCount),
                'id': messageNode['id'],
                't': str(int(time.time()))
            }
        ))

        signalStore = ISignalStore(self.authState)
        registrationId = yield maybeDeferred(signalStore.getLocalRegistrationId)

        receiptNode.addChild(Node(
            "registration", None, encodeUint(registrationId, 4)
        ))

        if retryCount > 1:
            identityKeyPair = yield maybeDeferred(signalStore.getIdentityKeyPair)
            signedPreKey = yield maybeDeferred(signalStore.loadSignedPreKey, -1)
            preKey = KeyHelper.generatePreKeys(self.authState.nextPreKeyId, 1)[0]
            yield maybeDeferred(signalStore.storePreKey, preKey.getId(), preKey)

            receiptNode.addChild(Node(
                "keys", None, [
                    Node("type", None, encodeUint(curve.Curve.DJB_TYPE, 1)),
                    Node("identity", None, identityKeyPair.getPublicKey().getPublicKey().getPublicKey()),
                    Node("key", None, [
                        Node("id", None, encodeUint(preKey.getId(), 3)),
                        Node("value", None, preKey.getKeyPair().getPublicKey().getPublicKey())
                    ]),
                    Node("skey", None, [
                        Node("id", None, encodeUint(signedPreKey.getId(), 3)),
                        Node("value", None, signedPreKey.getKeyPair().getPublicKey().getPublicKey()),
                        Node("signature", None, signedPreKey.getSignature())
                    ]),
                    self._buildDeviceIdentityNode()
                ]
            ))

        def callback(result):
            self.authState['nextPreKeyId'] += 1
            return result

        d = self.request(receiptNode).addCallback(callback)
        yield d

    def _authOK(self):
        self.log.info("Authentication Success, Restarting Connection")
        self.factory._authState = self.authState
        self.authState = None
        self._clearTransportCipher()


    def _sendStreamEnd(self):
        if not self._streamEndReceived:
            self.sendMessageNode(Node("xmlstreamend"))
            self._clearTransportCipher()

    _keepAliveLoop = None

    def _startKeepAliveLoop(self):
        @LoopingCall
        def loop():
            return self.request(Node(
                "iq", attributes={
                    'id': self._generateMessageId(),
                    'to': Constants.S_WHATSAPP_NET,
                    'type': "get",
                    'xmlns': "w:p"
                }, content=Node("ping")
            )).addErrback(lambda _: None)

        self._keepAliveLoop = loop
        self._keepAliveLoop.start(20, now=False)

    _qrDelayedCall = None

    def _startQrLoop(self, qrRefs):
        initial = [True]

        def resetDelayedCall():
            self._qrDelayedCall = None
            emitQR()

        def emitQR():
            try:
                qrRef = qrRefs.pop(0)
            except IndexError:
                try:
                    raise AuthenticationFailedError("QR Timeout")
                except:
                    self._sendStreamEnd()
                    self._handleFailure(Failure())
            else:
                def onIdentityKey(identityKeyPair):
                    if initial[0]:
                        initial[0] = False
                        timeout = 57
                    else:
                        timeout = 18

                    qrInfo = [
                        qrRef,
                        base64.b64encode(self.authState.noiseKey.getPublicKey().getPublicKey()),
                        base64.b64encode(identityKeyPair.getPublicKey().getPublicKey().getPublicKey()),
                        base64.b64encode(self.authState.advSecretKey)
                    ]

                    self.fire("qr", qrInfo).addErrback(evErrback)
                    self._qrDelayedCall = self.reactor.callLater(timeout, resetDelayedCall)

                signalStore = ISignalStore(self.authState)
                maybeDeferred(signalStore.getIdentityKeyPair).addCallback(
                    onIdentityKey
                ).addErrback(evErrback)

        def evErrback(f):
            self._sendStreamEnd()
            self._handleFailure(f)

        emitQR()

    def _stopQrLoop(self):
        if self._qrDelayedCall is not None:
            try:
                self._qrDelayedCall.cancel()
            except:
                pass
            self._qrDelayedCall = None

    _messageTagCounter = 0
    _messageTagPrefix = None

    def _generateMessageId(self):
        if self._messageTagPrefix is None:
            _1 = generateRandomNumber(5)
            _2 = generateRandomNumber(5)
            self._messageTagPrefix = "%s.%s" % (_1, _2, )

        suffix = str((self._messageTagCounter + 1))
        self._messageTagCounter += 1

        messageTag = "%s-%s" %(self._messageTagPrefix, suffix)

        if self._messageTagCounter == 99:
            self._messageTagPrefix = None
            self._messageTagCounter = 0

        return messageTag


class MultiDeviceWhatsAppClientFactory(WebSocketClientFactory):

    _authState = None
    _savedProtocol = None

    def __init__(self,
        url=None,
        origin=None,
        protocols=None,
        useragent=None,
        headers=None,
        proxy=None
    ):
        self.readyDeferred = Deferred()
        self.authDeferred = Deferred()
        WebSocketClientFactory.__init__(
            self, url=url, origin=origin, protocols=protocols,
            useragent=useragent, headers=headers, proxy=proxy)

    def buildProtocol(self, addr):
        protocol = self.protocol()

        if self._authState is not None:
            authState, self._authState = self._authState, None
            if protocol.authState is not None:
                protocol.authState = None
            protocol.authState = authState

        protocol.factory = self

        return protocol

    def _onOpen(self, connection):
        if self.readyDeferred is not None:
            d, self.readyDeferred = self.readyDeferred, None
            d.callback(connection)
        else:
            # handshake after authetication success
            connection._doHandshake().addErrback(connection._handleFailure)

    def _onClose(self, connection, reason=None):
        if self.readyDeferred is not None:
            d, self.readyDeferred = self.readyDeferred, None
            if reason is None:
                reason = ConnectionClosed(reason="Websocket Handshake Failed")
            d.errback(reason)

    def authFailure(self, failure):
        if self.authDeferred is not None:
            d, self.authDeferred = self.authDeferred, None
            d.errback(failure)

    def authSuccess(self, connection):
        if self.authDeferred is not None:
            d, self.authDeferred = self.authDeferred, None
            d.callback(connection)

    def clientConnectionFailed(self, connector, reason):
        if self.readyDeferred is not None:
            d, self.readyDeferred = self.readyDeferred, None
            d.errback(reason)

    def clientConnectionLost(self, connector, reason):
        if self._authState is not None:
            connector.connect()



def connectToWhatsAppServer(
    protocolFactory=None,
    host=Constants.WHATSAPP_WEBSOCKET_HOST,
    port=Constants.WHATSAPP_WEBSOCKET_PORT,
    url=Constants.WHATSAPP_WEBSOCKET_URL,
    useragent=Constants.DEFAULT_USER_AGENT,
    origin=Constants.DEFAULT_ORIGIN,
    reactor=None
):
    if reactor is None:
        from twisted.internet import reactor

    factory = MultiDeviceWhatsAppClientFactory(
        url=url,
        useragent=useragent,
        origin=origin)

    if protocolFactory is None:
        def _protocolFactory():
            authState = AuthState()
            return MultiDeviceWhatsAppClient(authState)
        protocolFactory = _protocolFactory

    factory.protocol = protocolFactory

    if host == Constants.WHATSAPP_WEBSOCKET_HOST:
        contextFactory = getTlsConnectionFactory()
        clientFactory = TLSMemoryBIOFactory(contextFactory, True, factory)
    else:
        clientFactory = factory

    reactor.connectTCP(host, port, clientFactory)
    return factory.readyDeferred
