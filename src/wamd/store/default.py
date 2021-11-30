import base64

from zope.interface import implementer

from axolotl.state.sessionrecord import SessionRecord
from axolotl.state.signedprekeyrecord import SignedPreKeyRecord
from axolotl.invalidkeyidexception import InvalidKeyIdException
from axolotl.state.prekeyrecord import PreKeyRecord
from axolotl.groups.state.senderkeyrecord import SenderKeyRecord


from wamd.iface import IJsonSerializable


@implementer(IJsonSerializable)
class DefaultMemoryStore:

    def __init__(self):
        self._sessionStore = {}
        self._identityKeyStore = {}
        self._preKeyStore = {}
        self._signedPrekeyStore = {}
        self._senderKeyStore = {}

    def loadSession(self, recipientId, deviceId):
        key = "%s:%s" % (recipientId, deviceId, )
        try:
            return self._sessionStore[key]
        except KeyError:
            return SessionRecord()

    def storeSession(self, recipientId, deviceId, sessionRecord):
        key = "%s:%s" % (recipientId, deviceId, )
        self._sessionStore[key] = sessionRecord

    def containSession(self, recipientId, deviceId):
        key = "%s:%s" % (recipientId, deviceId, )
        return key in self._sessionStore

    def removeSession(self, recipientId, deviceId):
        key = "%s:%s" % (recipientId, deviceId, )
        try:
            del self._sessionStore[key]
        except:
            pass

    def isTrustedIdentity(self, recipientId, theirIdentityKey):
        return True

    def saveIdentity(self, recipientId, identityKey):
        self._identityKeyStore[recipientId] = identityKey

    def removePreKey(self, preKeyId):
        try:
            del self._preKeyStore[preKeyId]
        except KeyError:
            pass

    def loadSignedPreKey(self, signedPreKeyId):
        try:
            return SignedPreKeyRecord(serialized=self._signedPrekeyStore[signedPreKeyId])
        except KeyError:
            raise InvalidKeyIdException("No such signedprekeyrecord!, signedPreKeyId: %s " % signedPreKeyId)

    def loadPreKey(self, preKeyId):
        try:
            return self._preKeyStore[preKeyId]
        except KeyError:
            raise InvalidKeyIdException("No Such Prekey!, preKeyId: %s" % (preKeyId, ))

    def storePreKey(self, preKeyId, preKey):
        self._preKeyStore[preKeyId] = preKey

    def removePreKey(self, preKeyId):
        try:
            del self._preKeyStore[preKeyId]
        except KeyError:
            pass

    def loadSenderKey(self, senderKeyName):
        key = senderKeyName.serialize() # Keep it simple
        try:
            return self._senderKeyStore[key]
        except KeyError:
            return SenderKeyRecord()

    def storeSenderKey(self, senderKeyName, senderKeyRecord):
        key = senderKeyName.serialize() # Keep it simple
        self._senderKeyStore[key] = senderKeyRecord

    def toJson(self):
        jsonDict = {}

        if self._preKeyStore:
            jsonDict['preKeys'] = {}
            for k in self._preKeyStore:
                preKey = self._preKeyStore[k]
                jsonDict['preKeys'][preKey.getId()] = base64.b64encode(preKey.serialize()).decode()

        if self._sessionStore:
            jsonDict['sessions'] = {}
            for recipientId, sessionRecord in self._sessionStore.items():
                jsonDict['sessions'][recipientId] = base64.b64encode(sessionRecord.serialize()).decode()

        if self._senderKeyStore:
            jsonDict['senderKeys'] = {}
            for key, senderKeyRecord in self._senderKeyStore.items():
                jsonDict['senderKeys'][key] = base64.b64encode(senderKeyRecord.serialize()).decode()

        return jsonDict

    def populate(self, jsonDict):
        try:
            preKeys = jsonDict.pop("preKeys")
        except KeyError:
            pass
        else:
            for k in preKeys:
                preKey = PreKeyRecord(serialized=base64.b64decode(preKeys[k]))
                self._preKeyStore[preKey.getId()] = preKey

        try:
            sessions = jsonDict.pop("sessions")
        except KeyError:
            pass
        else:
            for recipientId, serialized in sessions.items():
                self._sessionStore[recipientId] = SessionRecord(
                    serialized=base64.b64decode(serialized))

        try:
            senderKeys = jsonDict.pop("senderKeys")
        except KeyError:
            pass
        else:
            for key, serialized in senderKeys.items():
                self._senderKeyStore[key] = SenderKeyRecord(
                    serialized=base64.b64decode(serialized))
