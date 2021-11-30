import time

from .base import NodeHandler
from wamd.coder import Node
from wamd.utils import splitJid
from wamd.constants import Constants


class ReceiptHandler(NodeHandler):

    # <receipt
    #     from="628xxxxxxx@c.us"
    #     id="7A4387821D95F625990CC1B9CC56D400"
    #     recipient="628xxxxx@c.us"
    #     t="1636794944">
    # </receipt>

    def handleNode(self, conn, node):
        ackNode = Node(
            "ack", {
                'to': node['from'],
                'id': node['id'],
                'class': "receipt"
            })

        if node['participant'] is not None:
            ackNode['participant'] = node['participant']

        if node['type'] is not None:
            ackNode['type'] = node['type']

        try:
            conn.sendMessageNode(ackNode)
        finally: # ??? Is this necessary?
            conn.fire("receipt", conn, node)


class AckHandler(NodeHandler):

    def handleNode(self, conn, node):
        pending = self.getPendingRequestDeferred(conn, node['id'])
        if pending:
            pending.callback(node)
