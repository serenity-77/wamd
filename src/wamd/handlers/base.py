from twisted.logger import Logger


class NodeHandler(object):

    log = Logger()

    def __init__(self, reactor=None):
        if reactor is None:
            from twisted.internet import reactor
        self.reactor = reactor

    def getPendingRequestDeferred(self, conn, id):
        if id is not None and id in conn._pendingRequest:
            pending = conn._pendingRequest[id]
            del conn._pendingRequest[id]
            return pending
        return None

    def handleNode(self, conn, node):
        pass
