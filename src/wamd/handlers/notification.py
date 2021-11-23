from twisted.internet.defer import inlineCallbacks
from .base import NodeHandler
from wamd.coder import Node



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
            countNode = node.getChild("count")
            if countNode and countNode['value'] is not None:
                yield conn._uploadPreKeys()
