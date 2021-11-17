import os
import base64

from twisted.python.reflect import qual

from axolotl.ecc import curve, djbec, eckeypair
from axolotl.util.keyhelper import KeyHelper
from axolotl.identitykeypair import IdentityKeyPair
from axolotl.state.signedprekeyrecord import SignedPreKeyRecord


_INITIAL_ATTRIBUTES = [
    "signedIdentityKey",
    "noiseKey",
    "signedPrekey",
    "registrationId",
    "advSecretKey",
    "me"
]


class AuthState:

    def __init__(self, init=True, store=None):
        self.__dict__['_authState'] = {}

        if store is None:
            from .signalstore.default import DefaultMemoryStore
            store = DefaultMemoryStore()
            store.loadSignedPreKey = lambda keyId: self.signedPrekey
            store.getIdentityKeyPair = lambda: self.signedIdentityKey
            store.getLocalRegistrationId = lambda: self.registrationId

        self.__dict__['store'] = store

        if init:
            self._initKeys()

    def _initKeys(self):
        identityKeyPair = curve.Curve.generateKeyPair()
        self.signedIdentityKey = IdentityKeyPair(
            identityKeyPair.getPublicKey(),
            identityKeyPair.getPrivateKey()
        )
        self.noiseKey = curve.Curve.generateKeyPair()
        self.signedPrekey = KeyHelper.generateSignedPreKey(self.signedIdentityKey, 1)
        self.registrationId = KeyHelper.generateRegistrationId()
        self.advSecretKey = os.urandom(32)
        self.nextPrekeyId = 1
        self.serverHasPreKeys = False

    def __setattr__(self, name, value):
        self._setKeyValue(name, value)

    def __getattr__(self, name):
        try:
            return self._getValue(name)
        except KeyError:
            raise AttributeError("%s" % (name, ))

    def __setitem__(self, name, value):
        self._setKeyValue(name, value)

    def __getitem__(self, name):
        return self._getValue(name)

    def get(self, name, default=None):
        try:
            return self._getValue(name)
        except KeyError:
            return default

    def _setKeyValue(self, key, value):
        self._authState[key] = value

    def _getValue(self, key):
        return self._authState[key]

    def has(self, key):
        try:
            self._authState[key]
        except KeyError:
            return False
        return True

    def toJson(self):
        jsonDict = {}

        jsonDict['signedIdentityKey'] = {
            'private': base64.b64encode(self.signedIdentityKey.getPrivateKey().getPrivateKey()).decode(),
            'public': base64.b64encode(self.signedIdentityKey.getPublicKey().getPublicKey()).decode()
        }

        jsonDict['noiseKey'] = {
            'private': base64.b64encode(self.noiseKey.getPrivateKey().getPrivateKey()).decode(),
            'public': base64.b64encode(self.noiseKey.getPublicKey().getPublicKey()).decode()
        }

        jsonDict['signedPrekey'] = {
            'id': self.signedPrekey.getId(),
            'timestamp': self.signedPrekey.getTimestamp(),
            'keyPair': {
                'private': base64.b64encode(self.signedPrekey.getKeyPair().getPrivateKey().getPrivateKey()).decode(),
                'public': base64.b64encode(self.signedPrekey.getKeyPair().getPublicKey().getPublicKey()).decode()
            },
            'signature': base64.b64encode(self.signedPrekey.getSignature()).decode()
        }

        jsonDict['registrationId'] = self.registrationId
        jsonDict['advSecretKey'] = base64.b64encode(self.advSecretKey).decode()

        if self.has("me"):
            jsonDict['me'] = self.me

        for k, v in self._authState.items():
            if k not in _INITIAL_ATTRIBUTES:
                jsonDict[k] = v

        return jsonDict

    @classmethod
    def fromJson(cls, jsonDict):
        authState = cls(init=False)

        try:
            signedIdentityKey = jsonDict.pop("signedIdentityKey")
        except KeyError:
            pass
        else:
            authState.signedIdentityKey = IdentityKeyPair(
                djbec.DjbECPublicKey(base64.b64decode(signedIdentityKey['public'])),
                djbec.DjbECPrivateKey(base64.b64decode(signedIdentityKey['private'])))
            authState.identityKeyPair = authState.signedIdentityKey

        try:
            noiseKey = jsonDict.pop("noiseKey")
        except KeyError:
            pass
        else:
            authState.noiseKey = eckeypair.ECKeyPair(
                djbec.DjbECPublicKey(base64.b64decode(noiseKey['public'])),
                djbec.DjbECPrivateKey(base64.b64decode(noiseKey['private'])))

        try:
            signedPrekey = jsonDict.pop("signedPrekey")
        except KeyError:
            pass
        else:
            authState.signedPrekey = SignedPreKeyRecord(
                _id=signedPrekey['id'],
                timestamp=signedPrekey['timestamp'],
                ecKeyPair=eckeypair.ECKeyPair(
                    djbec.DjbECPublicKey(base64.b64decode(signedPrekey['keyPair']['public'])),
                    djbec.DjbECPrivateKey(base64.b64decode(signedPrekey['keyPair']['private']))
                ),
                signature=base64.b64decode(signedPrekey['signature']))

        try:
            registrationId = jsonDict.pop("registrationId")
        except KeyError:
            pass
        else:
            authState.registrationId = registrationId

        try:
            advSecretKey = jsonDict.pop("advSecretKey")
        except KeyError:
            pass
        else:
            authState.advSecretKey = base64.b64decode(advSecretKey)

        for k, v in jsonDict.items():
            setattr(authState, k, v)

        return authState

    def setStore(self, store):
        self.__dict__['store'] = store

    def __repr__(self):
        return "<%s Object at 0x%x %s>" % (qual(self.__class__), id(self), str(self.__dict__['_authState']))

    __str__ = __repr__
