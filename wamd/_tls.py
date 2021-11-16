from twisted.internet.ssl import ClientContextFactory
from twisted.protocols.tls import _ContextFactoryToConnectionFactory


_connectionFactory = None

def getTlsConnectionFactory():
    global _connectionFactory
    if _connectionFactory is None:
        _connectionFactory = _ContextFactoryToConnectionFactory(ClientContextFactory())
    return _connectionFactory
