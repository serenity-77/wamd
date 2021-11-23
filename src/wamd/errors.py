class WhatsAppError(Exception):
    pass

class ConnectionClosedError(WhatsAppError):

    def __init__(self, isLoggedOut=False, isAuthDone=True, reason=""):
        self.isLoggedOut = isLoggedOut
        self.isAuthDone = isAuthDone
        WhatsAppError.__init__(self, reason)


class AuthenticationFailedError(WhatsAppError):
    pass

class StreamEndError(WhatsAppError):
    pass


class HandlerNotFound(WhatsAppError):
    pass


class HttpRequestError(WhatsAppError):

    def __init__(self, code, phrase, content):
        self.code = code
        self.content = content
        WhatsAppError.__init__(self, phrase)


class InvalidMediaSignature(WhatsAppError):
    pass


class NodeStreamError(WhatsAppError):
    def __init__(self, code, message=""):
        self.code = code
        WhatsAppError.__init__(self, "StreamError: %s" % (self.code, ))



class SendMessageError(WhatsAppError):
    pass
