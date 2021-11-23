import os
import base64

from twisted.python.reflect import qual

from axolotl.ecc import curve, djbec, eckeypair
from axolotl.util.keyhelper import KeyHelper
from axolotl.identitykey import IdentityKey
from axolotl.identitykeypair import IdentityKeyPair
from axolotl.state.signedprekeyrecord import SignedPreKeyRecord


from .store.default import DefaultMemoryStore
from .iface import IJsonSerializable


_INITIAL_ATTRIBUTES = [
    "identityKey",
    "noiseKey",
    "signedPrekey",
    "registrationId",
    "advSecretKey",
    "me",
    "signalIdentity",
    "signedDeviceIdentity"
]


class AuthState:

    def __init__(self, init=True, store=None):
        self.__dict__['_authState'] = {}

        if store is None:
            store = DefaultMemoryStore()
            store.loadSignedPreKey = lambda keyId: self.signedPrekey
            store.getIdentityKeyPair = lambda: self.identityKey
            store.getLocalRegistrationId = lambda: self.registrationId

        self.__dict__['store'] = store

        if init:
            self._initKeys()

    def _initKeys(self):
        self.identityKey = KeyHelper.generateIdentityKeyPair()
        self.noiseKey = curve.Curve.generateKeyPair()
        self.signedPrekey = KeyHelper.generateSignedPreKey(self.identityKey, 1)
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

        jsonDict['identityKey'] = {
            'private': base64.b64encode(self.identityKey.getPrivateKey().getPrivateKey()).decode(),
            'public': base64.b64encode(self.identityKey.getPublicKey().getPublicKey().getPublicKey()).decode()
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

        if self.has("signalIdentity"):
            jsonDict['signalIdentity'] = {
                'identifier': self.signalIdentity['identifier'],
                'identifierKey': base64.b64encode(self.signalIdentity['identifierKey']).decode()
            }

        if self.has("signedDeviceIdentity"):
            jsonDict['signedDeviceIdentity'] = {
                'details': base64.b64encode(self.signedDeviceIdentity['details']).decode(),
                'accountSignature': base64.b64encode(self.signedDeviceIdentity['accountSignature']).decode(),
                'accountSignatureKey': base64.b64encode(self.signedDeviceIdentity['accountSignatureKey']).decode(),
                'deviceSignature': base64.b64encode(self.signedDeviceIdentity['deviceSignature']).decode()
            }

        store = self.__dict__['store']

        if IJsonSerializable.providedBy(store):
            # TODO
            # Async toJson
            jsonDictStore = store.toJson()
            if jsonDictStore:
                jsonDict['store'] = {}
                jsonDict['store'].update(jsonDictStore)

        for k, v in self._authState.items():
            if k not in _INITIAL_ATTRIBUTES:
                jsonDict[k] = v

        return jsonDict

    @classmethod
    def fromJson(cls, jsonDict):
        authState = cls(init=False)

        try:
            identityKey = jsonDict.pop("identityKey")
        except KeyError:
            pass
        else:
            authState.identityKey = IdentityKeyPair(
                IdentityKey(djbec.DjbECPublicKey(base64.b64decode(identityKey['public']))),
                djbec.DjbECPrivateKey(base64.b64decode(identityKey['private'])))

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

        try:
            signalIdentity = jsonDict.pop("signalIdentity")
        except KeyError:
            pass
        else:
            authState.signalIdentity = {
                'identifier': signalIdentity['identifier'],
                'identifierKey': base64.b64decode(signalIdentity['identifierKey'])
            }

        try:
            signedDeviceIdentity = jsonDict.pop("signedDeviceIdentity")
        except KeyError:
            pass
        else:
            authState.signedDeviceIdentity = {
                'details': base64.b64decode(signedDeviceIdentity['details']),
                'accountSignature': base64.b64decode(signedDeviceIdentity['accountSignature']),
                'accountSignatureKey': base64.b64decode(signedDeviceIdentity['accountSignatureKey']),
                'deviceSignature': base64.b64decode(signedDeviceIdentity['deviceSignature'])
            }

        if IJsonSerializable.providedBy(authState.store):
            try:
                jsonDictStore = jsonDict.pop("store")
            except KeyError:
                pass
            else:
                # TODO
                # Async populate
                authState.store.populate(jsonDictStore)

        for k, v in jsonDict.items():
            setattr(authState, k, v)

        return authState

    def setStore(self, store):
        self.__dict__['store'] = store

    def __repr__(self):
        return "<%s Object at 0x%x %s>" % (qual(self.__class__), id(self), str(self.__dict__['_authState']))

    __str__ = __repr__
