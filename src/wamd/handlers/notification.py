from twisted.internet.defer import inlineCallbacks, maybeDeferred, succeed

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
        if node['type'] == "encrypt":
            ackNode = yield self._handlePreKeysNotification(conn, node)
        elif node['type'] == "w:gp2":
            ackNode = yield self._handleGroupNotification(conn, node)
        elif node['type'] == "devices":
            ackNode = yield self._handleDevicesNotification(conn, node)
        elif node['type'] == "status":
            ackNode = yield self._handleStatusNotification(conn, node)
        elif node['type'] == "server_sync":
            ackNode = yield self._handleServerSyncNotification(conn, node)
        elif node['type'] == "account_sync":
            ackNode = yield self._handleAccountSyncNotification(conn, node)
        else:
            self.log.warn("Unhandled notification {type}", type=node['type'])
            ackNode = Node("ack", {
                'to': node['from'],
                'id': node['id'],
                'class': "notification",
            })

            if node['type'] is not None:
                ackNode['type'] = node['type']

        conn.sendMessageNode(ackNode)

    @inlineCallbacks
    def _handlePreKeysNotification(self, conn, node):
        child = node.getChild()

        ackNode = Node("ack", {
            'to': node['from'],
            'id': node['id'],
            'class': "notification"
        })

        if child is None:
            ackNode['type'] == "encrypt"
            return ackNode

        if child.tag == "count":
            uploadCount = Constants.MAX_PREKEYS_UPLOAD - int(child['value'])
            yield conn._uploadPreKeys(count=uploadCount)

        elif child.tag == "identity":
            pass

        return ackNode


    @inlineCallbacks
    def _handleGroupNotification(self, conn, node):
        groupStore = IGroupStore(conn.authState)
        child = node.getChild()

        groupId = node['from'].split("@")[0]

        ackNode = Node("ack", {
            'to': node['from'],
            'id': node['id'],
            'class': "notification"
        })

        if child.tag == "remove":
            participantJid = child.findChild("participant")['jid']
            participants = []
            if isJidSameUser(participantJid, conn.authState.me['jid']):
                # Kick
                for participant in (yield groupStore.getAllGroupParticipants(groupId)):
                    participants.append(participant['jid'])

                yield maybeDeferred(groupStore.removeGroupInfo, groupId)
                yield maybeDeferred(groupStore.removeAllFlaggedSenderKeys, groupId)

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

        if node['participant'] is not None:
            ackNode['participant'] = node['participant']

        return ackNode

    def _handleDevicesNotification(self, conn, node):
        return succeed(Node(
            "ack", {
                'to': node['from'],
                'id': node['id'],
                'class': "notification"
            }
        ))

    def _handleStatusNotification(self, conn, node):
        return succeed(Node(
            "ack", {
                'to': node['from'],
                'id': node['id'],
                'class': "notification",
                'type': "status"
            }
        ))

    def _handleServerSyncNotification(self, conn, node):
        return succeed(Node(
            "ack", {
                'to': node['from'],
                'id': node['id'],
                'class': "notification",
                'type': "server"
            }
        ))

    def _handleAccountSyncNotification(self, conn, node):
        return succeed(Node(
            "ack", {
                'to': node['from'],
                'id': node['id'],
                'class': "notification",
                'type': "account_sync"
            }
        ))
