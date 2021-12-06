import os
import base64

from twisted.internet.defer import inlineCallbacks, maybeDeferred
from twisted.python.reflect import qual
from twisted.python.components import Componentized

from axolotl.ecc import curve, djbec, eckeypair
from axolotl.util.keyhelper import KeyHelper

from .iface import (
    IJsonSerializableStore,
    ISignalStore,
    IGroupStore
)


_INITIAL_ATTRIBUTES = [
    "noiseKey",
    "advSecretKey",
    "me",
    "signalIdentity",
    "signedDeviceIdentity"
]


_STORE_INTERFACES = {
    '__SIGNALSTORE__': ISignalStore,
    '__GROUPSTORE__': IGroupStore
}


class AuthState(Componentized):

    def __init__(self):
        self._authState = {}
        Componentized.__init__(self)

        from .store.default import (
            DefaultMemorySignalStore,
            DefaultMemoryGroupStore,
            DefaultCachedMediaStore
        ) # Cyclic import

        defaultSignalStore = DefaultMemorySignalStore()
        defaultGroupStore = DefaultMemoryGroupStore()
        defaultCachedMediaStore = DefaultCachedMediaStore()

        self.addStoreComponent(defaultSignalStore)
        self.addStoreComponent(defaultGroupStore)
        self.addStoreComponent(defaultCachedMediaStore)

    @inlineCallbacks
    def initKeys(self):
        if self.has("initKeys"):
            return

        self['noiseKey'] = curve.Curve.generateKeyPair()
        self['advSecretKey'] = os.urandom(32)
        self['nextPreKeyId'] = 1
        self['serverHasPreKeys'] = False

        identityKeyPair = KeyHelper.generateIdentityKeyPair()
        signedPreKey = KeyHelper.generateSignedPreKey(identityKeyPair, 1)
        registrationId = KeyHelper.generateRegistrationId()

        signalStore = ISignalStore(self)

        yield maybeDeferred(signalStore.saveIdentityKeyPair, identityKeyPair)
        yield maybeDeferred(signalStore.storeSignedPreKey, signedPreKey.getId(), signedPreKey)
        yield maybeDeferred(signalStore.saveLocalRegistrationId, registrationId)

        self['initKeys'] = 1

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

        jsonDict['noiseKey'] = {
            'private': base64.b64encode(self.noiseKey.getPrivateKey().getPrivateKey()).decode(),
            'public': base64.b64encode(self.noiseKey.getPublicKey().getPublicKey()).decode()
        }

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

        for name, iface in _STORE_INTERFACES.items():
            store = iface(self)
            if IJsonSerializableStore.providedBy(store):
                jsonStore = store.toJson()
                if jsonStore:
                    jsonDict[name] = jsonStore

        for k, v in self._authState.items():
            if k not in _INITIAL_ATTRIBUTES:
                jsonDict[k] = v

        return jsonDict

    def populateFromJson(self, jsonDict):
        try:
            noiseKey = jsonDict.pop("noiseKey")
        except KeyError:
            pass
        else:
            self['noiseKey'] = eckeypair.ECKeyPair(
                djbec.DjbECPublicKey(base64.b64decode(noiseKey['public'])),
                djbec.DjbECPrivateKey(base64.b64decode(noiseKey['private'])))

        try:
            advSecretKey = jsonDict.pop("advSecretKey")
        except KeyError:
            pass
        else:
            self['advSecretKey'] = base64.b64decode(advSecretKey)

        try:
            signalIdentity = jsonDict.pop("signalIdentity")
        except KeyError:
            pass
        else:
            self['signalIdentity'] = {
                'identifier': signalIdentity['identifier'],
                'identifierKey': base64.b64decode(signalIdentity['identifierKey'])
            }

        try:
            signedDeviceIdentity = jsonDict.pop("signedDeviceIdentity")
        except KeyError:
            pass
        else:
            self['signedDeviceIdentity'] = {
                'details': base64.b64decode(signedDeviceIdentity['details']),
                'accountSignature': base64.b64decode(signedDeviceIdentity['accountSignature']),
                'accountSignatureKey': base64.b64decode(signedDeviceIdentity['accountSignatureKey']),
                'deviceSignature': base64.b64decode(signedDeviceIdentity['deviceSignature'])
            }

        for name, iface in _STORE_INTERFACES.items():
            store = iface(self)
            if IJsonSerializableStore.providedBy(store):
                try:
                    jsonDictStore = jsonDict.pop(name)
                except KeyError:
                    pass
                else:
                    store.populate(jsonDictStore)

        for k, v in jsonDict.items():
            self[k] = v

    def addStoreComponent(self, component):
        self.addComponent(component, ignoreClass=1)

    def __repr__(self):
        return "<%s Object at 0x%x %s>" % (qual(self.__class__), id(self), str(self._authState))

    __str__ = __repr__



class _NoKeyErrorDictMixin(dict):

    def __getitem__(self, item):
        try:
            return dict.__getitem__(self, item)
        except KeyError:
            return None


class GroupInfo(_NoKeyErrorDictMixin):
    def __init__(self, **kwargs):
        _NoKeyErrorDictMixin.__init__(self, **kwargs)


class GroupParticipant(_NoKeyErrorDictMixin):
    def __init__(self, **kwargs):
        _NoKeyErrorDictMixin.__init__(self, **kwargs)

    def __eq__(self, jid):
        if isinstance(jid, str):
            return jid == self['jid']
        return _NoKeyErrorDictMixin.__eq__(self)
