from twisted.internet.defer import inlineCallbacks
from twisted.python.failure import Failure

from axolotl.invalidkeyidexception import InvalidKeyIdException
from axolotl.invalidmessageexception import InvalidMessageException
from axolotl.duplicatemessagexception import DuplicateMessageException

from .base import NodeHandler
from wamd.coder import splitJid, Node, isJidSameUser
from wamd.signalhelper import decrypt as signalDecrypt
from wamd.proto import WAMessage_pb2
from wamd.utils import toHex, inflate, removeRandomPadding
from wamd.http import downloadMediaAndDecrypt
from wamd.messages import WhatsAppMessage


class MessageHandler(NodeHandler):
    """
    Conversation:
        <message from="6282124039728@c.us" type="text" id="9EB4A63A8B6885441AD1CA8DC21A9310" t="1636830303" verified_level="unknown" notify="Harianja Lundu" verified_name="8004297565368480738">
    	    <enc v="2" type="pkmsg">33080812210573898bf3aeaf81cb7dd64dd1a460ad0e5f97dbc5a36b601ce127e4fe55e6b4281a2105392080e84619550476aceafcd1d4b5eed87a5dcb253f05289aa5a27de6060d38229201330a2105811c80bd18aff331bcfb2f13f89dd200ee24502c029867d90f7dd3f05daaf7751000180022608715434401a046374af727a922b9c8cd4788ef4b367c0666aac6c0ea2930b0e4c06a8e7c05c4b3f90af4bb536d2f5704a85169c73fa40cc55644261bfd0c7b980be1a3d4d00ae7f75a0591c6d15d7585dab9d0fb49bf29d8ef2c159c69bc68f21300109bc8fef30228cfd1d583013001</enc>
    	    <verified_name v="1" verified_level="unknown">0a2208e2e7bfa2a2c7be8a6f1206736d623a7761220e48617269616e6a61204c756e647512409972c74e0e7400f89ea4fbe0cb8f2eeb927ef15bdc734329cc48d2af398877fe08a5e516a00a990074e3ff8abb11e844e1839537a419a626cac1c5e1f65a960b</verified_name>
    	</message>

        conversation: "the message here"
        messageContextInfo {
          deviceListMetadata {
            recipientKeyHash: "\341An\307l\021\215\336\251\365"
            recipientTimestamp: 1636830248
          }
          deviceListMetadataVersion: 2
        }
    Media:
        <message from="62857920832129@c.us" type="media" id="0AF51573F723CD2EBA315292AA83BC5F" t="1636833156" recipient="6282124039728@c.us" notify="LunduTest1">
	       <enc v="2" type="pkmsg" mediatype="image">33080712210579c481dbcbf62ff1908c2f830a409c9750ccd0022353b40f8006308b846d01351a210548bdaefa9c643560e189d7d4c2b5a0deb04ca412b65ac9864b3213ede621815322b309330a21057bdf6c7aa7c988327bbce5bfdff9d219fde6e1fdb7838aae666c610cd61b4a0510051800228009876e199b0572c0c90d0164c0a1e9627986bb2d6b87578ffe7e746eb485313caeb6e5da07935fab1702cb8d6a67c93e728a3acaff12b8a9225bf5bfa04a15e94563b304c900a3ce476579d9803a8b5defc002f5f5c794cbd7c6cbddbe77d54f5b5c3dcf5f91c33412f5443e6a1840dddfc68468b0783eb31a2843d781c01cdfdb193ce613ecfceca04299969d930d07f40b6dce25b5e178a1ff1a5e8aa119b01090d3bb33fa28b616037613a0276bf4b49a777509e28b5d1832eeabf56b39701fb44284c98a6f815d41a5853911c230374aee6315294729131ae3f9bb79b3023859284902679288f367a0c75b6d98cc0c54882477f335c3cc6cfdd9f2f67057f30e77398807b96d96e2c4a09899eaedae9c703a8e423f98f88a17665bca2c895c766a6441fa72d875004dce57153803d78c02f0db910367d0ba8a5e3b378c2ac3d48f6e316afb54eeb29e302b0af108051480c8a63e872808bf6867abfac0ebfe1fff831b0902a82ae05289786ceed44c7f3379c88effe5d079f553dafce87cf2364479e6522ab7bf4ae7cb72c9328ae7c0d9ce24b754552f3c161d571edffaab68c4b88603d789958d799c97fcd83d1dc65d4e2a57642e038f74dd0d9cb4f1ded8f9f685140e0a26f5e7f575be1725171a90d3ef291278bf5088d492866b922594233bf43d5ae7febd9353686ed6a052c86377f8679e49cf7b48ae42b7286e69e39821bc1d0bf1a34c9a6cd0350d7e596d4af0910deb54ab88c08174f16939d8994d16ad01ebb0811f8b290bedc9a66b19607e79b52a0de931216ce9b0e53f7eb22050bf250f7124c3b5bb35b35f0c9563c8d508cd9594dd634216192a33f871484ee0fc335b34ca55a550008be5271052a55805881ccd4f62efc772ffd3e86cf95b356bdda212c299041185a1a008e44544f3b3f186b7e3114de6106c9fc27282e51a4f6ec5b68f9d2f6427876aaafd4ba3938e80367114215d5602d8838219a80aced2a9c7f4506a1f46a5380cf4a79c9bae5f3d48b1c5f3f30007f8840f4f9952152a885460c8684a286e15da74319ddbfbe032ce00c2aff58253253b1a41b3f6e66af4ec298129e6d7c88768e4c8a4d8a816486924ae6ac12fafc03768c1ded4653211d71009e88ed951436d807df485d85356777dd11222beccadc5ef20e5aeef0e650f16eb8f5921104770188c505463db8cfbb8d7345d2862567a490cdd0b7acb495512e9619cd1eccefdb5e5896deaebcd992482278cebdd6159a81ae8051654a25e3f0c104c296d63830a18a209b6f308b85db8776b463327660cca2d0a20b9050fbf71b38590f6080df55042c2ab4cf42bf1254551b760a5d0f492f4c9b332411f01c881185c480b7e4f9ac9c69508ff53e23ca5c63ff61edc47a8daea8adf33323ba7fc72869826cae7635044d4141c24fc3cc48973d1e3277f06412317822868932fe82057d7cacf193ded2e8cb5b87c5bfbca15262c3ab866b5cd3f171f3e66eb636927065d977cd09b6cf8fbb61dcb23c56a638917a098d02a97e5398bc09be7f4dfabec5841f77899f02cc24663cfae1266a027068301e8a6be305532a5e3e12a8b17b6b9363513e4887b5a1a16faa785648ef283dfb235d6b8ebe57ad2c8159a28bc9d94e5053001</enc>
	    </message>
    """

    @inlineCallbacks
    def handleNode(self, conn, node):
        encNode = node.findChild("enc")
        user, _, _, server = splitJid(node['from'])

        if encNode is None:
            # Unavailable content
            return

        try:
            plainText = yield signalDecrypt(
                conn.authState.store,
                encNode.content,
                user,
                type=encNode['type'])
        except (InvalidKeyIdException, InvalidMessageException) as ex:
            self.log.warn("Incoming Message [{messageId}] Decrypt Failed, message={message}, Going to send retry request",
                messageId=node['id'], message=str(ex))
            # TODO
            # send receipt
            # If exception is InvalidKeyIdException, maybe request a retry
        except DuplicateMessageException:
            # From Yowsup
            self.log.warn("Received a message that we've previously decrypted")
        except:
            self.log.error("Decrypt Failure {failure}", failure=Failure())
        else:
            if encNode['v'] == "2":
                plainText = removeRandomPadding(plainText)

            self.log.debug("Decrypted PlainText: {plainText}", plainText=toHex(plainText))

            messageProto = WAMessage_pb2.Message()
            messageProto.ParseFromString(plainText)

            if messageProto.HasField("protocolMessage"):
                self._handleProtocolMessage(conn, node, messageProto.protocolMessage)
            else:
                self._sendReceipt(conn, node)
                self._handleIncomingMessage(conn, messageProto, node=node)


    def _handleProtocolMessage(self, conn, node, protocolMessage):
        if protocolMessage.type == WAMessage_pb2.ProtocolMessage.HISTORY_SYNC_NOTIFICATION:
            self._sendReceipt(conn, node)
            historySyncNotification = protocolMessage.historySyncNotification
            self._handleHistorySyncNotification(conn, node, historySyncNotification)


    @inlineCallbacks
    def _handleHistorySyncNotification(self, conn, node, historySyncNotification):
        messagePlaintext = yield downloadMediaAndDecrypt(
            historySyncNotification.directPath,
            historySyncNotification.mediaKey,
            "history")

        messagePlaintext = inflate(messagePlaintext)

        historySync = WAMessage_pb2.HistorySync()
        historySync.ParseFromString(messagePlaintext)

        if (
            historySync.syncType == WAMessage_pb2.HistorySyncNotification.INITIAL_BOOTSTRAP or
            historySync.syncType == WAMessage_pb2.HistorySyncNotification.RECENT
        ):
            if historySync.conversations:
                for conversation in historySync.conversations:
                    unreadCount = conversation.unreadCount
                    for historySyncMsg in conversation.messages:
                        webMessageInfoProto = historySyncMsg.message
                        isRead = True
                        if unreadCount > 0:
                            unreadCount -= 1
                            isRead = False
                        self._handleIncomingMessage(conn, webMessageInfoProto, isRead=isRead)

    def _handleIncomingMessage(self, conn, messageProto, node=None, isRead=False):
        if (
            not isinstance(messageProto, WAMessage_pb2.WebMessageInfo) and
            node is not None and
            messageProto.HasField("deviceSentMessage")
        ):
            # Message sent from own device
            m = WAMessage_pb2.Message()
            m.MergeFrom(messageProto.deviceSentMessage.message)
            messageProto = m
            node['fromMe'] = True

        try:
            message = WhatsAppMessage.fromMessageProto(messageProto, node=node, isRead=isRead)
        except:
            self.log.failure("Failed to parse from protocol message")
        else:
            conn.fire("inbox", conn, message)

    def _sendReceipt(self, conn, node):
        if node['category'] is not None and node['category'] == "peer":
            conn.sendMessageNode(Node(
                "receipt", {
                    'id': node['id'],
                    'to': node['from'],
                    'type': "peer_msg"
                }))
        elif isJidSameUser(node['from'], conn.authState.me['jid']):
            conn.sendMessageNode(Node(
                "receipt", {
                    'id': node['id'],
                    'to': node['from'],
                    'recipient': node['recipient'],
                    'type': "sender"
                }))
        else:
            conn.sendMessageNode(Node(
                "receipt", {
                    'id': node['id'],
                    'to': node['from'],
                }))
