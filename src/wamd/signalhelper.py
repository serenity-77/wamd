"""
A Wrapper around axolotl cipher that maybe use
an async storage.

Literally everything is copied from python-axolotl
"""
import random

from twisted.internet.defer import maybeDeferred, inlineCallbacks
from twisted.python.reflect import qual

from axolotl.protocol.prekeywhispermessage import PreKeyWhisperMessage
from axolotl.protocol.whispermessage import WhisperMessage
from axolotl.ratchet.bobaxolotlparamaters import BobAxolotlParameters
from axolotl.ratchet.ratchetingsession import RatchetingSession
from axolotl.ratchet.aliceaxolotlparameters import AliceAxolotlParameters
from axolotl.state.sessionstate import SessionState
from axolotl.sessioncipher import AESCipher
from axolotl.untrustedidentityexception import UntrustedIdentityException
from axolotl.invalidmessageexception import InvalidMessageException
from axolotl.duplicatemessagexception import DuplicateMessageException
from axolotl.invalidkeyexception import InvalidKeyException
from axolotl.nosessionexception import NoSessionException
from axolotl.ecc.curve import Curve

from .coder import decodeInt

_MEDIUM_MAX_VALUE = 0xFFFFFF


@inlineCallbacks
def decrypt(authState, cipherText, recipientId, deviceId=1, type="pkmsg", unpad=True):
    if type == "pkmsg":
        plainText = yield _decryptPkMsg(
            authState, PreKeyWhisperMessage(serialized=cipherText),
            recipientId, deviceId)

    elif type == "msg":
        plainText = yield _decryptMsg(
            authState, WhisperMessage(serialized=cipherText),
            recipientId, deviceId)

    else:
        raise NotImplementedError("Type: %s not implemented" % (type, ))

    if unpad:
        unpadLength = decodeInt(plainText[-1:], 1) & 0xFF
        plainText = plainText[:-unpadLength]

    return plainText


@inlineCallbacks
def encrypt(authState, plainText, recipientId, deviceId=1):
    padNum = random.randint(1, 255)
    paddedMessage = plainText + bytes([padNum] * padNum)

    sessionRecord = yield maybeDeferred(
        authState.store.loadSession, recipientId, deviceId)

    sessionState = sessionRecord.getSessionState()
    chainKey = sessionState.getSenderChainKey()
    messageKeys = chainKey.getMessageKeys()
    senderEphemeral = sessionState.getSenderRatchetKey()
    previousCounter = sessionState.getPreviousCounter()
    sessionVersion = sessionState.getSessionVersion()

    ciphertextBody = _getCipherText(messageKeys, paddedMessage)
    ciphertextMessage = WhisperMessage(sessionVersion, messageKeys.getMacKey(),
                                       senderEphemeral, chainKey.getIndex(),
                                       previousCounter, ciphertextBody,
                                       sessionState.getLocalIdentityKey(),
                                       sessionState.getRemoteIdentityKey())

    if sessionState.hasUnacknowledgedPreKeyMessage():
        items = sessionState.getUnacknowledgedPreKeyMessageItems()
        localRegistrationId = sessionState.getLocalRegistrationId()

        ciphertextMessage = PreKeyWhisperMessage(sessionVersion, localRegistrationId, items.getPreKeyId(),
                                                 items.getSignedPreKeyId(), items.getBaseKey(),
                                                 sessionState.getLocalIdentityKey(),
                                                 ciphertextMessage)

    sessionState.setSenderChainKey(chainKey.getNextChainKey())

    yield maybeDeferred(
        authState.store.storeSession, recipientId, deviceId, sessionRecord)

    if isinstance(ciphertextMessage, PreKeyWhisperMessage):
        type = "pkmsg"
    elif isinstance(ciphertextMessage, WhisperMessage):
        type = "msg"
    else:
        raise NotImplementedError("%s cipher text is not implemented" % qual(ciphertextMessage.__class__))

    type = "pkmsg" if isinstance(ciphertextMessage, PreKeyWhisperMessage) else "msg"
    return type, ciphertextMessage.serialize()


@inlineCallbacks
def _decryptPkMsg(authState, message, recipientId, deviceId):
    sessionRecord = yield maybeDeferred(
        authState.store.loadSession, recipientId, deviceId)

    theirIdentityKey = message.getIdentityKey()

    isTrustedIdentity = yield maybeDeferred(
        authState.store.isTrustedIdentity, recipientId, theirIdentityKey)

    if not isTrustedIdentity:
        raise UntrustedIdentityException(recipientId, theirIdentityKey)

    unsignedPreKeyId = yield _processV3(authState, sessionRecord, message)

    # if unsignedPreKeyId is not None:
    #     yield maybeDeferred(authState.store.removePreKey, unsignedPreKeyId)

    yield maybeDeferred(authState.store.saveIdentity, recipientId, theirIdentityKey)

    return _decryptWithSessionRecord(sessionRecord, message.getWhisperMessage())


@inlineCallbacks
def _decryptMsg(authState, cipherText, recipientId, deviceId=1):
    sessionExists = yield maybeDeferred(
        authState.store.containSession, recipientId, deviceId)

    if not sessionExists:
        raise NoSessionException("No session for: %s, %s" % (recipientId, deviceId))

    sessionRecord = yield maybeDeferred(
        authState.store.loadSession, recipientId, deviceId)

    plaintext = _decryptWithSessionRecord(sessionRecord, cipherText)

    yield maybeDeferred(
        authState.store.storeSession, recipientId, deviceId, sessionRecord)

    return plaintext


@inlineCallbacks
def _processV3(authState, sessionRecord, message):
    if sessionRecord.hasSessionState(
        message.getMessageVersion(), message.getBaseKey().serialize()
    ):
        return None

    signedPrekey = yield maybeDeferred(
        authState.store.loadSignedPreKey, message.getSignedPreKeyId())
    ourSignedPreKey = signedPrekey.getKeyPair()

    identityKeyPair = yield maybeDeferred(authState.store.getIdentityKeyPair)

    parameters = BobAxolotlParameters.newBuilder()
    parameters.setTheirBaseKey(message.getBaseKey())\
        .setTheirIdentityKey(message.getIdentityKey())\
        .setOurIdentityKey(identityKeyPair)\
        .setOurSignedPreKey(ourSignedPreKey)\
        .setOurRatchetKey(ourSignedPreKey)

    if message.getPreKeyId() is not None:
        preKey = yield maybeDeferred(
            authState.store.loadPreKey, message.getPreKeyId())
        parameters.setOurOneTimePreKey(preKey.getKeyPair())
    else:
        parameters.setOurOneTimePreKey(None)

    if not sessionRecord.isFresh():
        sessionRecord.archiveCurrentState()

    RatchetingSession.initializeSessionAsBob(
        sessionRecord.getSessionState(), parameters.create())

    localRegistrationid = yield maybeDeferred(authState.store.getLocalRegistrationId)
    sessionRecord.getSessionState().setLocalRegistrationId(localRegistrationid)
    sessionRecord.getSessionState().setRemoteRegistrationId(message.getRegistrationId())
    sessionRecord.getSessionState().setAliceBaseKey(message.getBaseKey().serialize())

    if message.getPreKeyId() is not None and message.getPreKeyId() != _MEDIUM_MAX_VALUE:
        return message.getPreKeyId()

    return None


def _decryptWithSessionRecord(sessionRecord, cipherText):
    previousStates = sessionRecord.getPreviousSessionStates()
    exceptions = []
    try:
        sessionState = SessionState(sessionRecord.getSessionState())
        plaintext = _decryptWithSessionState(sessionState, cipherText)
        sessionRecord.setState(sessionState)
        return plaintext
    except InvalidMessageException as e:
        exceptions.append(e)

    for i in range(0, len(previousStates)):
        previousState = previousStates[i]
        try:
            promotedState = SessionState(previousState)
            plaintext = _decryptWithSessionState(promotedState, cipherText)
            previousStates.pop(i)
            sessionRecord.promoteState(promotedState)
            return plaintext
        except InvalidMessageException as e:
            exceptions.append(e)

    raise InvalidMessageException("No valid sessions", exceptions)


def _decryptWithSessionState(sessionState, ciphertextMessage):
    if not sessionState.hasSenderChain():
        raise InvalidMessageException("Uninitialized session!")

    if ciphertextMessage.getMessageVersion() != sessionState.getSessionVersion():
        raise InvalidMessageException("Message version %s, but session version %s" % (ciphertextMessage.getMessageVersion, sessionState.getSessionVersion()))

    messageVersion = ciphertextMessage.getMessageVersion()
    theirEphemeral = ciphertextMessage.getSenderRatchetKey()
    counter = ciphertextMessage.getCounter()
    chainKey = _getOrCreateChainKey(sessionState, theirEphemeral)
    messageKeys = _getOrCreateMessageKeys(sessionState, theirEphemeral, chainKey, counter)

    ciphertextMessage.verifyMac(messageVersion,
                                sessionState.getRemoteIdentityKey(),
                                sessionState.getLocalIdentityKey(),
                                messageKeys.getMacKey())

    plaintext = _getPlainText(messageVersion, messageKeys, ciphertextMessage.getBody())
    sessionState.clearUnacknowledgedPreKeyMessage()

    return plaintext


def _getOrCreateChainKey(sessionState, ECPublickKey_theirEphemeral):
    theirEphemeral = ECPublickKey_theirEphemeral
    if sessionState.hasReceiverChain(theirEphemeral):
        return sessionState.getReceiverChainKey(theirEphemeral)
    else:
        rootKey = sessionState.getRootKey()
        ourEphemeral = sessionState.getSenderRatchetKeyPair()
        receiverChain = rootKey.createChain(theirEphemeral, ourEphemeral)
        ourNewEphemeral = Curve.generateKeyPair()
        senderChain = receiverChain[0].createChain(theirEphemeral, ourNewEphemeral)

        sessionState.setRootKey(senderChain[0])
        sessionState.addReceiverChain(theirEphemeral, receiverChain[1])
        sessionState.setPreviousCounter(max(sessionState.getSenderChainKey().getIndex() - 1, 0))
        sessionState.setSenderChain(ourNewEphemeral, senderChain[1])
        return receiverChain[1]


def _getOrCreateMessageKeys(sessionState, ECPublicKey_theirEphemeral, chainKey, counter):
    theirEphemeral = ECPublicKey_theirEphemeral
    if chainKey.getIndex() > counter:
        if sessionState.hasMessageKeys(theirEphemeral, counter):
            return sessionState.removeMessageKeys(theirEphemeral, counter)
        else:
            raise DuplicateMessageException("Received message with old counter: %s, %s" % (chainKey.getIndex(),
                                                                                           counter))

    if counter - chainKey.getIndex() > 2000:
        raise InvalidMessageException("Over 2000 messages into the future!")

    while chainKey.getIndex() < counter:
        messageKeys = chainKey.getMessageKeys()
        sessionState.setMessageKeys(theirEphemeral, messageKeys)
        chainKey = chainKey.getNextChainKey()

    sessionState.setReceiverChainKey(theirEphemeral, chainKey.getNextChainKey())
    return chainKey.getMessageKeys()


def _getPlainText(version, messageKeys, cipherText):
    cipher = AESCipher(messageKeys.getCipherKey(), messageKeys.getIv())
    return cipher.decrypt(cipherText)

def _getCipherText(messageKeys, plainText):
    cipher = AESCipher(messageKeys.getCipherKey(), messageKeys.getIv())
    return cipher.encrypt(plainText)


@inlineCallbacks
def processPreKeyBundle(authState, preKey, recipientId, deviceId=1):
    isTrustedIdentity = yield maybeDeferred(
        authState.store.isTrustedIdentity, recipientId, preKey.getIdentityKey())

    if not isTrustedIdentity:
        raise UntrustedIdentityException(recipientId, preKey.getIdentityKey())

    if preKey.getSignedPreKey() is not None and\
        not Curve.verifySignature(preKey.getIdentityKey().getPublicKey(),
                                  preKey.getSignedPreKey().serialize(),
                                  preKey.getSignedPreKeySignature()):
        raise InvalidKeyException("Invalid signature on device key!")

    if preKey.getSignedPreKey() is None:
        raise InvalidKeyException("No signed prekey!!")

    sessionRecord = yield maybeDeferred(
        authState.store.loadSession, recipientId, deviceId)

    ourBaseKey = Curve.generateKeyPair()
    theirSignedPreKey = preKey.getSignedPreKey()
    theirOneTimePreKey = preKey.getPreKey()
    theirOneTimePreKeyId = preKey.getPreKeyId() if theirOneTimePreKey is not None else None

    parameters = AliceAxolotlParameters.newBuilder()

    identityKeyPair = yield maybeDeferred(authState.store.getIdentityKeyPair)

    parameters.setOurBaseKey(ourBaseKey)\
        .setOurIdentityKey(identityKeyPair)\
        .setTheirIdentityKey(preKey.getIdentityKey())\
        .setTheirSignedPreKey(theirSignedPreKey)\
        .setTheirRatchetKey(theirSignedPreKey)\
        .setTheirOneTimePreKey(theirOneTimePreKey)

    if not sessionRecord.isFresh():
        sessionRecord.archiveCurrentState()

    RatchetingSession.initializeSessionAsAlice(sessionRecord.getSessionState(), parameters.create())

    sessionRecord.getSessionState().setUnacknowledgedPreKeyMessage(theirOneTimePreKeyId,
                                                                   preKey.getSignedPreKeyId(),
                                                                   ourBaseKey.getPublicKey())

    localRegistrationId = yield maybeDeferred(authState.store.getLocalRegistrationId)

    sessionRecord.getSessionState().setLocalRegistrationId(localRegistrationId)
    sessionRecord.getSessionState().setRemoteRegistrationId(preKey.getRegistrationId())
    sessionRecord.getSessionState().setAliceBaseKey(ourBaseKey.getPublicKey().serialize())

    yield maybeDeferred(
        authState.store.storeSession, recipientId, deviceId, sessionRecord)

    yield maybeDeferred(
        authState.store.saveIdentity, recipientId, preKey.getIdentityKey())
