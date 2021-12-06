import base64

from zope.interface import implementer
from twisted.logger import Logger

from axolotl.state.sessionrecord import SessionRecord
from axolotl.state.signedprekeyrecord import SignedPreKeyRecord
from axolotl.invalidkeyidexception import InvalidKeyIdException
from axolotl.state.prekeyrecord import PreKeyRecord
from axolotl.groups.state.senderkeyrecord import SenderKeyRecord
from axolotl.ecc import djbec, eckeypair
from axolotl.identitykey import IdentityKey
from axolotl.identitykeypair import IdentityKeyPair

from wamd.iface import (
    ISignalStore,
    IJsonSerializableStore,
    IGroupStore,
    ICachedMediaStore
)

from wamd.common import GroupInfo, GroupParticipant
from wamd.utils import splitJid


@implementer(ISignalStore, IJsonSerializableStore)
class DefaultMemorySignalStore:

    identityKeyPair = None
    signedPreKey = None
    registrationId = None

    def __init__(self):
        self._sessionStore = {}
        self._identityKeyStore = {}
        self._preKeyStore = {}
        self._signedPrekeyStore = {}
        self._senderKeyStore = {}

    def saveIdentityKeyPair(self, identityKeyPair):
        self.identityKeyPair = identityKeyPair

    def getIdentityKeyPair(self):
        return self.identityKeyPair

    def storeSignedPreKey(self, signedPreKeyId, signedPreKeyRecord):
        self.signedPreKey = signedPreKeyRecord

    def loadSignedPreKey(self, signedPreKeyId):
        return self.signedPreKey

    def saveLocalRegistrationId(self, registrationId):
        self.registrationId = registrationId

    def getLocalRegistrationId(self):
        return self.registrationId

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

    def removeSenderKey(self, senderKeyName):
        key = senderKeyName.serialize()
        try:
            del self._senderKeyStore[key]
        except KeyError:
            pass

    def toJson(self):
        jsonDict = {}

        jsonDict['identityKeyPair'] = {
            'private': base64.b64encode(self.identityKeyPair.getPrivateKey().getPrivateKey()).decode(),
            'public': base64.b64encode(self.identityKeyPair.getPublicKey().getPublicKey().getPublicKey()).decode()
        }

        jsonDict['signedPreKey'] = {
            'id': self.signedPreKey.getId(),
            'timestamp': self.signedPreKey.getTimestamp(),
            'keyPair': {
                'private': base64.b64encode(self.signedPreKey.getKeyPair().getPrivateKey().getPrivateKey()).decode(),
                'public': base64.b64encode(self.signedPreKey.getKeyPair().getPublicKey().getPublicKey()).decode()
            },
            'signature': base64.b64encode(self.signedPreKey.getSignature()).decode()
        }

        jsonDict['registrationId'] = self.registrationId

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
            identityKeyPair = jsonDict.pop("identityKeyPair")
        except KeyError:
            pass
        else:
            self.identityKeyPair = IdentityKeyPair(
                IdentityKey(djbec.DjbECPublicKey(base64.b64decode(identityKeyPair['public']))),
                djbec.DjbECPrivateKey(base64.b64decode(identityKeyPair['private'])))

        try:
            signedPreKey = jsonDict.pop("signedPreKey")
        except KeyError:
            pass
        else:
            self.signedPreKey = SignedPreKeyRecord(
                _id=signedPreKey['id'],
                timestamp=signedPreKey['timestamp'],
                ecKeyPair=eckeypair.ECKeyPair(
                    djbec.DjbECPublicKey(base64.b64decode(signedPreKey['keyPair']['public'])),
                    djbec.DjbECPrivateKey(base64.b64decode(signedPreKey['keyPair']['private']))
                ),
                signature=base64.b64decode(signedPreKey['signature']))

        try:
            registrationId = jsonDict.pop("registrationId")
        except KeyError:
            pass
        else:
            self.registrationId = registrationId

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


# IGroupStore
@implementer(IGroupStore, IJsonSerializableStore)
class DefaultMemoryGroupStore:

    def __init__(self):
        self._groupInfo = {}
        self._senderKeyFlags = {}

    def storeGroupInfo(self, groupInfo):
        groupId = groupInfo['id']
        self._groupInfo[groupId] = groupInfo

    def removeGroupInfo(self, groupId):
        try:
            del self._groupInfo[groupId]
        except KeyError:
            pass

    def storeGroupParticipant(self, groupId, participant):
        if self._groupInfo[groupId]['participants'] is None:
            self._groupInfo[groupId]['participants'] = {}
        self._groupInfo[groupId]['participants'][participant['jid']] = participant

    def removeGroupParticipant(self, groupId, participantJid):
        try:
            del self._groupInfo[groupId]['participants'][participantJid]
        except KeyError:
            pass

    def groupExists(self, groupId):
        return groupId in self._groupInfo

    def getAllGroupParticipants(self, groupId):
        try:
            return list(self._groupInfo[groupId]['participants'].values())
        except KeyError:
            return []

    def getAllGroupInfo(self):
        return [GroupInfo(**info) for id, info in self._groupInfo.items()]

    def flagSenderKey(self, groupId, participant):
        try:
            self._senderKeyFlags[groupId]
        except KeyError:
            self._senderKeyFlags[groupId] = []

        if participant not in self._senderKeyFlags[groupId]:
            self._senderKeyFlags[groupId].append(participant)

    def removeSenderKeyFlag(self, groupId, participant):
        try:
            self._senderKeyFlags[groupId]
        except KeyError:
            pass
        else:
            try:
                self._senderKeyFlags[groupId].remove(participant)
            except:
                pass

    def getAllFlaggedSenderKeys(self, groupId):
        try:
            p = self._senderKeyFlags[groupId][:]
        except KeyError:
            return []
        return p

    def toJson(self):
        jsonDict = {}
        if self._groupInfo:
            jsonDict['groupInfo'] = self._groupInfo

        if self._senderKeyFlags:
            jsonDict['senderKeyFlags'] = self._senderKeyFlags

        return jsonDict

    def populate(self, jsonDict):
        if not jsonDict:
            return

        try:
            groupInfo = jsonDict.pop("groupInfo")
        except KeyError:
            pass
        else:
            for groupId, info in groupInfo.items():
                try:
                    participants = info['participants']
                    del info['participants']
                except KeyError:
                    participants = {}

                groupInfo = GroupInfo(**info)
                for pId, participant in participants.items():
                    p = GroupParticipant(**participant)
                    if groupInfo['participants'] is None:
                        groupInfo['participants'] = {}
                    groupInfo['participants'][pId] = p

                self._groupInfo[groupId] = groupInfo

        try:
            senderKeyFlags = jsonDict.pop("senderKeyFlags")
        except KeyError:
            pass
        else:
            self._senderKeyFlags = senderKeyFlags


@implementer(ICachedMediaStore)
class DefaultCachedMediaStore:

    log = Logger()

    def __init__(self, removeTimeout=300, reactor=None):
        if reactor is None:
            from twisted.internet import reactor
        self._reactor = reactor
        self._removeTimeout = removeTimeout
        self._cachedMediaStore = {}

    def saveCachedMedia(self, key, mediaData):
        self._cachedMediaStore[key] = {}
        self._cachedMediaStore[key]['data'] = mediaData
        self._cachedMediaStore[key]['delayedCall'] = self._addTimeout(key)

    def getCachedMedia(self, key):
        try:
            return self._cachedMediaStore[key]['data']
        except KeyError:
            return None

    def _addTimeout(self, key):
        delayedCall = self._reactor.callLater(
            self._removeTimeout, self._onTimedOut, key)
        return delayedCall

    def _onTimedOut(self, key):
        self.log.debug("Removing {key} due to remove timeout", key=key)
        del self._cachedMediaStore[key]['delayedCall']
        del self._cachedMediaStore[key]['data']
        del self._cachedMediaStore[key]
