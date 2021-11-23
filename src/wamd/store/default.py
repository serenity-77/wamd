import base64

from zope.interface import implementer

from axolotl.state.sessionrecord import SessionRecord
from axolotl.state.signedprekeyrecord import SignedPreKeyRecord
from axolotl.invalidkeyidexception import InvalidKeyIdException
from axolotl.state.prekeyrecord import PreKeyRecord

from wamd.iface import IJsonSerializable


@implementer(IJsonSerializable)
class DefaultMemoryStore:

    def __init__(self):
        self._sessionStore = {}
        self._identityKeyStore = {}
        self._preKeyStore = {}
        self._signedPrekeyStore = {}

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

    def toJson(self):
        jsonDict = {}

        if self._preKeyStore:
            jsonDict['preKeys'] = {}
            for k in self._preKeyStore:
                preKey = self._preKeyStore[k]
                jsonDict['preKeys'][preKey.getId()] = base64.b64encode(preKey.serialize()).decode()

        if self._sessionStore:
            jsonDict['sessions'] = {}
            for recipientId in self._sessionStore:
                sessionRecord = self._sessionStore[recipientId]
                jsonDict['sessions'][recipientId] = base64.b64encode(sessionRecord.serialize()).decode()

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
