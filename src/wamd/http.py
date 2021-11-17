from zope.interface import implementer
from urllib.parse import urlparse, urlencode

from twisted.internet import reactor
from twisted.internet.defer import maybeDeferred, Deferred, inlineCallbacks
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



def _defaultRequestFactory(url, method=b"GET", data=None, headers=None):
    if not isinstance(url, bytes):
        url = url.encode()

    if not isinstance(method, bytes):
        method = method.encode()

    bodyProducer = None

    if method == b"GET" and data is not None:
        parsedUrl = urlparse(url)
        qs = urlencode(data).encode()
        if parsedUrl.query:
            qs = parsedUrl.query + b"&" + qs

        url = parsedUrl.scheme + b"://" + parsedUrl.netloc + parsedUrl.path + b"?" + qs
    else:
        pass

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


def request(url, method=b"GET", data=None, headers=None):
    """
    Perform http request
    """

    return maybeDeferred(
        _requestFactory,
        url,
        method=method,
        data=data,
        headers=headers)


@inlineCallbacks
def downloadMediaAndDecrypt(directPath, mediaKey, mediaType):
    if not directPath.startswith("https:"):
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
