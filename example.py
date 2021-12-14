import sys
import pyqrcode
import json

from io import BytesIO

# twisted imports
from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks
from twisted.python.filepath import FilePath
from twisted.python.failure import Failure
from twisted.logger import (
    textFileLogObserver,
    FilteringLogObserver,
    LogLevelFilterPredicate,
    LogLevel,
    globalLogPublisher,
    Logger
)


from wamd.protocol import connectToWhatsAppServer, MultiDeviceWhatsAppClient
from wamd.common import AuthState




globalLogPublisher.addObserver(
    FilteringLogObserver(
        observer=textFileLogObserver(sys.stdout, timeFormat="%Y-%M-%d %H:%M:%S"),
        predicates=[LogLevelFilterPredicate(defaultLogLevel=LogLevel.levelWithName("debug"))] # or info
    )
)


log = Logger()


def protocolFactory():
    authState = AuthState()
    sessionPath = FilePath("session.json")

    if sessionPath.exists():
        try:
            with open(sessionPath.path, "r") as f:
                session = json.loads(f.read())
                authState.populateFromJson(session)
        except:
            raise
    else:
        authState = None

    return MultiDeviceWhatsAppClient(authState)


def handleQr(qrInfo):
    # this will require pyqrcode installed
    # or whatever library or package used to
    # render qr code.

    log.info("QR Info: {qrInfo}", qrInfo=qrInfo)

    qrObj = pyqrcode.create(b",".join(qrInfo), error="L")
    qrIO = BytesIO()
    qrObj.png(qrIO, scale=6)
    qrBytes = qrIO.getvalue()
    qrIO.close()

    # This will create a png file named qr.png
    # Open it and scan it.
    with open("qr.png", "wb") as qrFileIO:
        qrFileIO.write(qrBytes)


@inlineCallbacks
def onConnect(connection):
    if not connection.authState.has("me"):
        connection.on("qr", handleQr)

    try:
        # On first login (Scanning QR) the connection
        # returned from connection.authenticate will
        # be different from the parameter of onConnect.
        # This is because after successfull pairing the
        # connection is restarted. So attach any event
        # to the connection only after successfull call to
        # connection.authenticate.
        connection = yield connection.authenticate()
    except:
        log.failure("Login Failure")
    else:
        log.info("Login Success")



connectToWhatsAppServer(
    protocolFactory=protocolFactory
).addCallback(
    onConnect
).addErrback(
    lambda f: log.failure("Connect Failure", failure=f)
)

reactor.run()
