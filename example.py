import sys
import pyqrcode

from io import BytesIO

from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks, maybeDeferred

from wamd.protocol import connectToWhatsAppServer, MultiDeviceWhatsAppClientProtocol
from wamd.messages import TextMessage, MediaMessage


from twisted.logger import (
    textFileLogObserver,
    FilteringLogObserver,
    LogLevelFilterPredicate,
    LogLevel,
    globalLogPublisher
)


globalLogPublisher.addObserver(
    FilteringLogObserver(
        observer=textFileLogObserver(sys.stdout, timeFormat="%Y-%M-%d %H:%M:%S"),
        predicates=[LogLevelFilterPredicate(defaultLogLevel=LogLevel.levelWithName("debug"))] # or info
    )
)


def protocolFactory():
    # Do any initialization here, such as reading session file
    # to be supplied to the protocol/connection.
    return MultiDeviceWhatsAppClientProtocol()


def handleQr(qrInfo):
    # this will require pyqrcode installed
    # or whatever library or package used to
    # render qr code

    print("\nQR Info: %r" % (qrInfo))
    qrObj = pyqrcode.create(b",".join(qrInfo), error="L")
    qrIO = BytesIO()
    qrObj.png(qrIO, scale=6)
    qrBytes = qrIO.getvalue()
    qrIO.close()

    with open("qr.png", "wb") as qrFileIO:
        qrFileIO.write(qrBytes)


def inboxReceiver(connection, message):
    print("Inbox Message: %s" % (message, ))
    if not message['fromMe'] and not message['isRead']:
        connection.sendReadReceipt(message)


@inlineCallbacks
def onConnect(connection):
    print("\nConnection 1: %r" % (connection, ))
    connection.on("qr", handleQr)

    # the new connection after successfull authentication
    # will be different than provided the first connection
    # since the connection will automatically be restarted
    # after authentication.
    connection = yield connection.authenticate()

    connection.on("inbox", inboxReceiver)
    print("\nConnection 2: %r" % (connection, ))



connectToWhatsAppServer(
    protocolFactory=protocolFactory
).addCallback(
    onConnect
).addErrback(
    lambda f: print("\nFailure : %s" % (f, ))
)

reactor.run()
