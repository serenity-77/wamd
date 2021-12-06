from twisted.internet.defer import inlineCallbacks
from twisted.python.failure import Failure

from .base import NodeHandler
from wamd.coder import Node
from wamd.utils import splitJid
from wamd.constants import Constants
from wamd.conn_utils import addGroupInfo


class SuccessHandler(NodeHandler):

    @inlineCallbacks
    def handleNode(self, conn, node):
        isFirstLogin = False

        if not conn.authState.serverHasPreKeys:
            yield conn._uploadPreKeys()
            conn.authState['serverHasPreKeys'] = True
            isFirstLogin = True

        yield conn.request(
            Node("iq", {
                'to': "@s.whatsapp.net",
                'xmlns': "passive",
                'type': "set",
                'id': conn._generateMessageId()
            }, Node("active")))

        self.log.info("Logged in with: {user}", user=conn.authState.me['jid'])

        if isFirstLogin:
            try:
                yield self._maybeFetchAndStoreGroupInfo(conn)
            except:
                conn._sendLogOut()
                conn._sendStreamEnd()
                raise

        conn.factory.authSuccess(conn)

    @inlineCallbacks
    def _maybeFetchAndStoreGroupInfo(self, conn):
        iqGroupResult = yield conn.request(Node(
            "iq", {
                'to': Constants.G_US,
                'type': "get",
                'xmlns': "w:g2",
                'id': conn._generateMessageId(),
            }, Node("participating", None, [
                Node("participants"),
                Node("description")
            ])
        ))

        groups = iqGroupResult.findChild("groups").findChilds("group")

        for group in groups:
            yield addGroupInfo(conn, group)
