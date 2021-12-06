from twisted.internet.defer import inlineCallbacks, maybeDeferred

from .base import NodeHandler
from wamd.coder import Node
from wamd.utils import splitJid, isJidSameUser, jidNormalize
from wamd.constants import Constants
from wamd.iface import ISignalStore, IGroupStore
from wamd.common import GroupInfo, GroupParticipant
from wamd.signalhelper import SenderKeyName
from wamd.conn_utils import addGroupInfo


class NotificationHandler(NodeHandler):

    @inlineCallbacks
    def handleNode(self, conn, node):
        ackNode = Node("ack", {
            'to': node['from'],
            'id': node['id'],
            'class': "notification"
        })

        if node['participant'] is not None:
            # For Group Notification
            ackNode['participant'] = node['participant']
        elif node['type'] is not None and node['type'] != "devices":
            ackNode['type'] = node['type']

        conn.sendMessageNode(ackNode)

        if node['type'] == "encrypt":
            yield self._handlePreKeysNotification(conn, node)

        elif node['type'] == "w:gp2":
            yield self._handleGroupNotification(conn, node)

    @inlineCallbacks
    def _handlePreKeysNotification(self, conn, node):
        countNode = node.getChild("count")
        if countNode and countNode['value'] is not None:
            uploadCount = Constants.MAX_PREKEYS_UPLOAD - int(countNode['value'])
            yield conn._uploadPreKeys(count=uploadCount)


    @inlineCallbacks
    def _handleGroupNotification(self, conn, node):
        groupStore = IGroupStore(conn.authState)
        child = node.getChild()

        groupId = node['from'].split("@")[0]

        if child.tag == "remove":
            participantJid = child.findChild("participant")['jid']
            participants = []
            if isJidSameUser(participantJid, conn.authState.me['jid']):
                # Kick
                for participant in (yield groupStore.getAllGroupParticipants(groupId)):
                    participants.append(participant['jid'])

                yield maybeDeferred(groupStore.removeGroupInfo, groupId)

            else:
                yield maybeDeferred(
                    groupStore.removeGroupParticipant, groupId, participantJid)
                participants.append(participantJid)

            # remove sender key, if present.
            signalStore = ISignalStore(conn.authState)

            for participant in participants:
                yield maybeDeferred(
                    signalStore.removeSenderKey,
                    SenderKeyName.create(groupId, participant.split("@")[0]))


        elif child.tag == "add":
            participant = child.findChild("participant")
            p = GroupParticipant(**participant.attributes)
            yield maybeDeferred(groupStore.storeGroupParticipant, groupId, p)

        elif child.tag == "create":
            yield addGroupInfo(conn, child.findChild("group"))
