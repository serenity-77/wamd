from twisted.internet.defer import inlineCallbacks
from .base import NodeHandler
from wamd.coder import Node
from wamd.utils import splitJid
from wamd.constants import Constants


class NotificationHandler(NodeHandler):

    @inlineCallbacks
    def handleNode(self, conn, node):
        conn.sendMessageNode(
            Node("ack", {
                'class': "notification",
                'id': node['id'],
                'type': node['type'],
                'to': node['from']
            }))

        if node['type'] == "encrypt":
            yield self._handlePrekeysNotification(conn, node)

        elif node['type'] == "account_sync":
            yield self._handleAccountSyncNotification(conn, node)

    @inlineCallbacks
    def _handlePrekeysNotification(self, conn, node):
        countNode = node.getChild("count")
        if countNode and countNode['value'] is not None:
            uploadCount = Constants.MAX_PREKEYS_UPLOAD - int(countNode['value'])
            yield conn._uploadPreKeys(count=uploadCount)

    @inlineCallbacks
    def _handleAccountSyncNotification(self, conn, node):
        devices = node.getChild("devices")

        if devices:
            if not conn.authState.has("syncedDevice"):
                conn.authState['syncedDevice'] = {
                    'dhash': devices['dhash'],
                    'devices': []
                }
            else:
                conn.authState['syncedDevice']['dhash'] = devices['dhash']

            deviceList = []
            _, _, meDeviceN, _ = splitJid(conn.authState.me['jid'])

            for device in devices.findChilds("device"):
                user, _, deviceN, server = splitJid(device['jid'])
                if deviceN != meDeviceN:
                    deviceList.append(device['jid'])

            for jid in conn.authState.syncedDevice['devices']:
                if jid not in deviceList:
                    yield conn.authState.store.removeSession(jid.split("@")[0], 1)

            conn.authState['syncedDevice']['devices'] = deviceList
