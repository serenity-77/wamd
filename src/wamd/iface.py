from zope.interface import Interface, Attribute


class ISignalStore(Interface):

    def loadSession(recipientId, deviceId):
        pass

    def storeSession(recipientId, deviceId, sessionRecord):
        pass

    def containSession(recipientId, deviceId):
        pass

    def removeSession(recipientId, deviceId):
        pass

    def isTrustedIdentity(recipientId, theirIdentityKey):
        pass

    def saveIdentity(recipientId, identityKey):
        pass

    def loadPreKey(preKeyId):
        pass

    def storePreKey(preKeyId, preKey):
        pass

    def removePreKey(preKeyId):
        pass

    def storeSignedPreKey(signedPreKeyId, signedPreKeyRecord):
        pass

    def loadSignedPreKey(signedPreKeyId):
        pass

    def saveIdentityKeyPair(self, identityKeyPair):
        pass

    def getIdentityKeyPair():
        pass

    def saveLocalRegistrationId():
        pass

    def getLocalRegistrationId():
        pass

    def loadSenderKey(senderKeyName):
        pass

    def storeSenderKey(senderKeyName, senderKeyRecord):
        pass

    def removeSenderKey(senderKeyname):
        pass


class IJsonSerializableStore(Interface):

    def toJson():
        pass

    def populate(self, jsonDict):
        pass


class IGroupStore(Interface):

    def storeGroupInfo(groupInfo):
        pass

    def removeGroupInfo(groupId):
        pass

    def storeGroupParticipant(groupId, groupParticipant):
        pass

    def removeGroupParticipant(groupId, participantJid):
        pass

    def groupExists(groupId):
        pass

    def getAllGroupParticipants(groupId):
        """
        return List(wamd.common.GroupParticipant)
        or Deferred that will fire with
        List(wamd.common._GroupParticipant)
        """

    def getAllGroupInfo():
        """
        return List(wamd.common.GroupInfo)
        """

    def flagSenderKey(groupId, participant):
        """
        Flag a sender key as sent to a participant
        """

    def removeSenderKeyFlag(groupId, participant):
        pass

    def getAllFlaggedSenderKeys(groupId):
        pass

    def removeAllFlaggedSenderKeys(groupId):
        pass


class ICachedMediaStore(Interface):

    def saveCachedMedia(self, key, mediaData):
        pass

    def getCachedMedia(self, key):
        pass


class IMessageStore(Interface):
    """
    Only used as a cache for message that
    needs to be retried.
    """

    def storeMessage(id, message):
        pass

    def getMessage(id):
        pass

    def removeMessage(id):
        pass

    def getAllMessageId():
        pass
