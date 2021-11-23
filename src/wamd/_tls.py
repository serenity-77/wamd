from twisted.internet.ssl import ClientContextFactory
from twisted.protocols.tls import _ContextFactoryToConnectionFactory
from twisted.internet._sslverify import optionsForClientTLS


def getTlsConnectionFactory(hostname=None):
    if hostname is None:
        _connectionFactory = _ContextFactoryToConnectionFactory(ClientContextFactory())
    else:
        if isinstance(hostname, bytes):
            hostname = hostname.decode()
        _connectionFactory = optionsForClientTLS(hostname)
    return _connectionFactory
