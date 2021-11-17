from .iq import IqHandler
from .stream_error import StreamErrorHandler
from .success import SuccessHandler
from .ib import IbHandler
from .notification import NotificationHandler
from .failure import FailureHandler
from .message import MessageHandler
from .ack_receipt import ReceiptHandler, AckHandler

from wamd.errors import HandlerNotFound

_HandlerMaps = {
    'iq': IqHandler,
    'stream:error': StreamErrorHandler,
    'success': SuccessHandler,
    'ib': IbHandler,
    'notification': NotificationHandler,
    'failure': FailureHandler,
    'message': MessageHandler,
    'receipt': ReceiptHandler,
    'ack': AckHandler
}


def createNodeHander(tag, *args, **kwargs):
    try:
        return _HandlerMaps[tag](*args, **kwargs)
    except KeyError:
        raise HandlerNotFound("Handler for [%s] not found" % (tag, ))
