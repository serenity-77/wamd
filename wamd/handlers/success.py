from twisted.internet.defer import inlineCallbacks

from .base import NodeHandler
from wamd.coder import splitJid, Node


class SuccessHandler(NodeHandler):

    @inlineCallbacks
    def handleNode(self, conn, node):
        yield conn._uploadPreKeys()

        yield conn.request(
            Node("iq", {
                'to': "@s.whatsapp.net",
                'xmlns': "passive",
                'type': "set",
                'id': conn._generateMessageId()
            }, Node("active")))

        user, agent, device, server = splitJid(conn.authState.me['jid'])
        self.log.info("Logged in with: {user}", user=user)
        conn.factory.authSuccess(conn)
