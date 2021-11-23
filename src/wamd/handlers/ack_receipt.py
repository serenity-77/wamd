from .base import NodeHandler
from wamd.coder import splitJid, Node


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

        if node['type'] is not None:
            ackNode['type'] = node['type']

        conn.sendMessageNode(ackNode)


class AckHandler(NodeHandler):

    def handleNode(self, conn, node):
        selfJid = conn.deviceJid

        if selfJid == node['from'] and node['class'] == "receipt" and node['type'] == "peer_msg":
            conn.sendMessageNode(Node(
                "receipt", {
                    'to': selfJid,
                    'type': "hist_sync",
                    'id': node['id']
                }))

        elif node['class'] == "message":
            pending = self.getPendingRequestDeferred(conn, node['id'])
            if pending:
                pending.callback(node)
