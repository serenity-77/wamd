from zope.interface import implementer
from urllib.parse import urlparse, urlencode, quote

from twisted.internet import reactor
from twisted.internet.defer import maybeDeferred, Deferred, inlineCallbacks, succeed
from twisted.web.client import Agent, readBody
from twisted.web.iweb import IPolicyForHTTPS, IBodyProducer
from twisted.web.http_headers import Headers

from ._tls import getTlsConnectionFactory
from .errors import HttpRequestError
from .utils import decryptMedia
from .constants import Constants


@implementer(IPolicyForHTTPS)
class WebClientContextFactory:
    def creatorForNetloc(self, hostname, port):
        return getTlsConnectionFactory()


_agent = Agent(reactor, contextFactory=WebClientContextFactory())


def _readBody(response, finished):
    code, phrase = response.code, response.phrase

    def done(content):
        if code != 200:
            finished.errback(HttpRequestError(code, phrase.decode(), content))
        else:
            finished.callback(content)

    d = readBody(response)
    d.addCallback(done)
    d.addErrback(lambda f: finished.errback(f))


implementer(IBodyProducer)
class HttpRequestBodyProducer(object):

    _WRITE_COUNT = 2 ** 16
    _paused = False

    def __init__(self, data, clock=None):
        if clock is None:
            from twisted.internet import reactor
            clock = reactor
        self._clock = clock
        if isinstance(data, dict):
            self._data = urlencode(data).encode()
        else:
            self._data = data
        self._length = len(self._data)
        self._finished = Deferred()
        self._finished.addCallback(self._writeFinished)
        self._nwrite = 0
        self._consumer = None

    @property
    def length(self):
        return self._length

    def startProducing(self, consumer):
        self._consumer = consumer
        self._scheduleWrite()
        return self._finished

    _delayedCall = None

    def _scheduleWrite(self):
        if self._delayedCall is None:
            self._delayedCall = self._clock.callLater(0, self._doWrite)

    def resumeProducing(self):
        self._paused = False
        self._scheduleWrite()

    def _doWrite(self):
        self._delayedCall = None

        if self._paused:
            return

        written = self._data[self._nwrite:self._nwrite + self.__class__._WRITE_COUNT]
        self._nwrite += len(written)

        self._consumer.write(written)

        if self._nwrite == self._length:
            self._finished.callback(None)
        else:
            self._scheduleWrite()

    def stopProducing(self):
        if not hasattr(self, "_finished"):
            return
        del self._finished
        del self._data
        del self._nwrite
        del self._consumer
        del self._clock

    def _writeFinished(self, ignore):
        self.stopProducing()

    def pauseProducing(self):
        self._paused = True


def _defaultRequestFactory(url, method=b"GET", data=None, query=None, headers=None, reactor=None):
    if not isinstance(url, bytes):
        url = url.encode()

    if not isinstance(method, bytes):
        method = method.encode()

    bodyProducer = None

    if query is not None:
        parsedUrl = urlparse(url)

        qs = urlencode(query).encode()

        if parsedUrl.query:
            qs = parsedUrl.query + b"&" + qs

        requestPath = parsedUrl.path
        if requestPath.endswith(b"/"):
            requestPath = requestPath.rstrip(b"/")

        requestPath = quote(requestPath).encode()
        url = parsedUrl.scheme + b"://" + parsedUrl.netloc + requestPath + b"?" + qs

    if method != b"GET" and data is not None:
        bodyProducer = HttpRequestBodyProducer(data, clock=reactor)
        
    if headers is not None:
        tmpHeaders = {}
        for k, v in headers.items():
            if not isinstance(v, list):
                tmpHeaders[k] = [v]
            else:
                tmpHeaders[k] = v
        headers = Headers(tmpHeaders)

    d = _agent.request(method, url, headers=headers, bodyProducer=bodyProducer)
    finished = Deferred()
    d.addCallback(lambda response: _readBody(response, finished))
    d.addErrback(lambda f: finished.errback(f))
    return finished


_requestFactory = None

def setDefaultRequestFactory(requestFactory, reactor=None):
    global _requestFactory
    _requestFactory = requestFactory


setDefaultRequestFactory(_defaultRequestFactory)


def request(url, method=b"GET", data=None, query=None, headers=None, reactor=None):
    """
    Perform http request
    """

    if reactor is None:
        from twisted.internet import reactor

    return maybeDeferred(
        _requestFactory,
        url,
        method=method,
        data=data,
        query=query,
        headers=headers,
        reactor=reactor)


@inlineCallbacks
def downloadMediaAndDecrypt(directPath, mediaKey, mediaType):
    if not (directPath.startswith("https:") or directPath.startswith("http:")):
        mediaUrl = "https://%s/%s" % (Constants.MEDIA_HOST.rstrip("/"), directPath.lstrip("/"))
    else:
        mediaUrl = directPath

    headers = {
        'Origin': Constants.WHATSAPP_WEBSOCKET_HOST.rstrip("/"),
        'Referer': Constants.WHATSAPP_WEBSOCKET_HOST.rstrip("/") + "/",
        'User-Agent': Constants.WHATSAPP_WEBSOCKET_HOST.rstrip("/")
    }

    result = yield request(mediaUrl, headers=headers)

    return decryptMedia(result, mediaKey, mediaType)
