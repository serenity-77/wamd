from twisted.internet.defer import inlineCallbacks, maybeDeferred
from twisted.python.reflect import qual

from axolotl.ecc import djbec
from axolotl.state.prekeybundle import PreKeyBundle
from axolotl.identitykey import IdentityKey

from .base import NodeHandler
from wamd.coder import Node
from wamd.utils import splitJid, isJidSameUser, decodeUint
from wamd.constants import Constants
from wamd.iface import IMessageStore, ISignalStore
from wamd.signalhelper import processPreKeyBundle
from wamd.messages import WhatsAppMessage
from wamd.proto import WAMessage_pb2


class ReceiptHandler(NodeHandler):

    # <receipt
    #     from="628xxxxxxx@c.us"
    #     id="7A4387821D95F625990CC1B9CC56D400"
    #     recipient="628xxxxx@c.us"
    #     t="1636794944">
    # </receipt>

    @inlineCallbacks
    def handleNode(self, conn, node):
        ackNode = Node("ack", {
            'to': node['from'],
            'id': node['id'],
            'class': "receipt"
        })

        if node['participant'] is not None:
            ackNode['participant'] = node['participant']

        if node['type'] is not None:
            ackNode['type'] = node['type']

        if node['type'] == "retry":
            try:
                yield self._handleRetryRequest(conn, node)
            except:
                self.log.failure("Failed to handle retry message")
        else:
            # yield self._handleReceiptCounter(conn, node)
            # maybe later if clear about delivered receipts.
            conn.fire("receipt", conn, node)

        conn.sendMessageNode(ackNode)

    @inlineCallbacks
    def _handleRetryRequest(self, conn, node):
        messageStore = IMessageStore(conn.authState)

        try:
            webMessageInfoBytes = yield maybeDeferred(messageStore.getMessage, node['id'])
        except:
            self.log.failure("Failed to fetch message for retry")
            return

        if not webMessageInfoBytes:
            self.log.warn("{messageStore} doesn't have the message [{id}]", messageStore=qual(IMessageStore), id=node['id'])
            return

        keysNode = node.findChild("keys")
        retryCount = int(node.findChild("retry")['count'])

        if retryCount == 5:
            self.log.warn("Retry receipt count maximum=5")
            return

        if keysNode is not None:
            signedPreKeyNode = keysNode.findChild("skey")
            preKeyNode = keysNode.findChild("key")

            registrationId = decodeUint(node.findChild("registration").content, 4)
            identityKey = IdentityKey(djbec.DjbECPublicKey(keysNode.findChild("identity").content))
            signedPreKeyId = decodeUint(signedPreKeyNode.findChild("id").content, 3)
            signedPreKeyPublic = djbec.DjbECPublicKey(signedPreKeyNode.findChild("value").content)
            signedPreKeySignature = signedPreKeyNode.findChild("signature").content

            if preKeyNode is None:
                preKeyId = None
                preKeyPublic = None
            else:
                preKeyId = decodeUint(preKeyNode.findChild("id").getContent(), 3)
                preKeyPublic = djbec.DjbECPublicKey(preKeyNode.findChild("value").content)

            preKeyBundle = PreKeyBundle(
                registrationId, 1, preKeyId, preKeyPublic,
                signedPreKeyId, signedPreKeyPublic, signedPreKeySignature,
                identityKey)

            if node['participant'] is not None:
                recipientId = node['participant'].split("@")[0]
            else:
                recipientId = node['from'].split("@")[0]

            yield processPreKeyBundle(
                ISignalStore(conn.authState), preKeyBundle, recipientId)

        webMessageInfoProto = WAMessage_pb2.WebMessageInfo()
        webMessageInfoProto.ParseFromString(webMessageInfoBytes)

        webMessageInfoProto.key.remoteJid = node['from']
        if node['participant'] is not None:
            webMessageInfoProto.key.participant = node['participant']

        messageNode = yield conn._makeRetryMessageNode(webMessageInfoProto, retryCount)

        yield conn.request(messageNode)

    @inlineCallbacks
    def _handleReceiptCounter(self, conn, node):
        if node['participant'] is not None:
            _from = node['participant']
        else:
            _from = node['from']

        if isJidSameUser(_from, conn.authState.me['jid']):
            return

        messageStore = IMessageStore(conn.authState)

        if node['type'] is None:
            _, _, device, _ = splitJid(_from)
            if not device:
                yield maybeDeferred(messageStore.incrementReceiptCounter, node['id'])

        elif node['type'] == "read":
            yield maybeDeferred(messageStore.incrementReadCounter, node['id'])


class AckHandler(NodeHandler):

    def handleNode(self, conn, node):
        pending = self.getPendingRequestDeferred(conn, node['id'])
        if pending:
            pending.callback(node)
