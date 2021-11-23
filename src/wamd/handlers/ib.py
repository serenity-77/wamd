from .base import NodeHandler
from ..errors import AuthenticationFailedError


class IbHandler(NodeHandler):

    def handleNode(self, conn, node):
        if node.findChild("downgrade_webclient") is not None:
            raise AuthenticationFailedError("Downgrade Web Client")
