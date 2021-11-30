from twisted.python.failure import Failure

from .base import NodeHandler
from wamd.errors import AuthenticationFailedError, NodeStreamError


class StreamErrorHandler(NodeHandler):

    def handleNode(self, conn, node):
        code = node['code']

        if code is not None:
            if code == "515" and not conn._authDone():
                conn._authOK()
            else:
                if conn._authDone():
                    failure = Failure(NodeStreamError(code=code))
                else:
                    failure = Failure(
                        AuthenticationFailedError(
                            "Authentication Failed: %s" % (code, )))

                conn._handleFailure(failure)

        else:
            conn._handleFailure(NodeStreamError(message="\n" + str(node)))
