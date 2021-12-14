class WAMDError(Exception):
    pass

class ConnectionClosed(WAMDError):

    def __init__(self, isLoggedOut=False, reason=""):
        self.isLoggedOut = isLoggedOut
        WAMDError.__init__(self, reason)


class AuthenticationFailedError(WAMDError):
    pass

class StreamEndError(WAMDError):
    pass


class HandlerNotFound(WAMDError):
    pass


class HttpRequestError(WAMDError):

    def __init__(self, code, phrase, content):
        self.code = code
        self.content = content
        WAMDError.__init__(self, phrase)


class InvalidMediaSignature(WAMDError):
    pass


class NodeStreamError(WAMDError):
    def __init__(self, code=None, message=""):
        self.code = code
        if self.code is not None:
            m = "Stream Error: %s" % (self.code)
        else:
            m = message
        WAMDError.__init__(self, m)


class IqRequestError(WAMDError):
    pass
