from axolotl.state.sessionrecord import SessionRecord
from axolotl.state.signedprekeyrecord import SignedPreKeyRecord
from axolotl.invalidkeyidexception import InvalidKeyIdException
from axolotl.invalidkeyexception import InvalidKeyException


class DefaultMemoryStore:

    def __init__(self):
        self._sessionStore = {}
        self._identityKeyStore = {}
        self._preKeyStore = {}
        self._signedPrekeyStore = {}

    def loadSession(self, recipientId, deviceId):
        key = "%s:%s" % (recipientId, deviceId, )
        try:
            return SessionRecord(serialized=self._sessionStore[key])
        except KeyError:
            return SessionRecord()

    def storeSession(self, recipientId, deviceId, sessionRecord):
        key = "%s:%s" % (recipientId, deviceId, )
        self._sessionStore[key] = sessionRecord.serialize()

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
            raise InvalidKeyException("No Such Prekey!, preKeyId: %s" % (preKeyId, ))

    def storePreKey(self, preKeyId, preKey):
        self._preKeyStore[preKeyId] = preKey

    def removePreKey(self, preKeyId):
        try:
            del self._preKeyStore[preKeyId]
        except KeyError:
            pass
