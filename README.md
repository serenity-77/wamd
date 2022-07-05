WhatsApp Web Multi Device client API

Literally everything combined from:
1. https://github.com/adiwajshing/baileys/tree/multi-device
2. https://github.com/tgalal/yowsup
3. https://github.com/sigalor/whatsapp-web-reveng
4. https://github.com/tulir/whatsmeow


Installation:
```shell
 git clone git@github.com:Serenity-77/wamd.git
 cd wamd
 pip3 install -r requirements.txt
 python3 setup.py install --record install.txt
```

Or using venv:
```shell
python3 -m venv venv
source venv/bin/activate
git clone git@github.com:harianjalundu77/wamd.git
cd wamd
pip install -r requirements.txt
python setup.py install --record install.txt
```

if this error occured during installation:

```shell
Traceback (most recent call last):
  File "<string>", line 1, in <module>
  File "/tmp/pip-build-a86ixoex/cryptography/setup.py", line 14, in <module>
    from setuptools_rust import RustExtension
ModuleNotFoundError: No module named 'setuptools_rust'
```

Update the pip:
```shell
pip install --upgrade pip
```
and re-run the installation

Uninstall:
```shell
xargs rm -rf < install.txt
```

Example:
```python
import sys
import json
import pyqrcode

# guard for pyqrcode
# This is here because this example use pyqrcode
# which require pypng installed
import png


from io import BytesIO

# Twisted Imports
from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks
from twisted.internet.task import deferLater
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
from wamd.messages import TextMessage


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
def handleInbox(connection, message):
    if not message['fromMe'] and not message['isRead']:
        log.info("Unread Message: {unreadMessage}", unreadMessage=message)

        # Send Read Receipt
        yield connection.sendReadReceipt(message)

        # Wait 5 seconds and then reply the message
        yield deferLater(reactor, 5)

        message = TextMessage(
            to=message['from'],
            conversation="What's up?"
        )

        try:
            result = yield connection.relayMessage(message)
        except:
            log.failure("Send message failure")
        else:
            log.info("Result: {result}", result=result)


def handleReceipt(connection, receipt):
    log.info("Got Receipt: {receipt}", receipt=receipt)


def handleClose(connection, reason):
    log.info("Handle Close: {reason}", reason=reason)

    sessionPath = FilePath("session.json")
    if reason.value.isLoggedOut:
        try:
            sessionPath.remove()
        except:
            pass
    else:
        with open(sessionPath.path, "w") as f:
            f.write(json.dumps(connection.authState.toJson(), indent=4))


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
        connection.on("inbox", handleInbox)
        connection.on("receipt", handleReceipt)
        connection.on("close", handleClose)



connectToWhatsAppServer(
    protocolFactory=protocolFactory
).addCallback(
    onConnect
).addErrback(
    lambda f: log.failure("Connect Failure", failure=f)
)

reactor.run()
```
