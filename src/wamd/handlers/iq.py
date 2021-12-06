import base64

from twisted.internet.defer import inlineCallbacks, maybeDeferred
from twisted.logger import Logger
from axolotl.ecc import curve, djbec

from wamd.coder import Node
from wamd.proto import WAMessage_pb2
from wamd.utils import hmacValidate

from .base import NodeHandler
from wamd.iface import ISignalStore
from wamd.constants import Constants


class IqHandler(NodeHandler):

    log = Logger()

    @inlineCallbacks
    def handleNode(self, conn, node):
        pending = self.getPendingRequestDeferred(conn, node['id'])
        if pending:
            pending.callback(node)
        elif not conn._authDone():
            yield self._handlePairing(conn, node)

    @inlineCallbacks
    def _handlePairing(self, conn, node):
        child = node.getChild()

        if child.tag == "pair-device":
            refNodes = node.children[0].getChilds("ref")

            conn.sendMessageNode(Node(
                "iq", attributes={
                    'to': Constants.S_WHATSAPP_NET,
                    'type': "result",
                    'id': node['id']
                }
            ))

            conn._startQrLoop([ref.content for ref in refNodes])

        elif child.tag == "pair-success":
            conn._stopQrLoop()

            c = node.children[0].findChild("device-identity")
            deviceIdentity = c.content
            c = node.children[0].findChild("device")
            jid = c['jid']

            signedDeviceIdentityHmac = WAMessage_pb2.ADVSignedDeviceIdentityHMAC()
            signedDeviceIdentityHmac.ParseFromString(deviceIdentity)

            if not hmacValidate(
                conn.authState.advSecretKey,
                signedDeviceIdentityHmac.hmac,
                signedDeviceIdentityHmac.details
            ):
                raise AuthenticationFailedError("Invalid pairing")

            signedDeviceIdentity = WAMessage_pb2.ADVSignedDeviceIdentity()
            signedDeviceIdentity.ParseFromString(signedDeviceIdentityHmac.details)

            signalStore = ISignalStore(conn.authState)
            identityKeyPair = yield maybeDeferred(signalStore.getIdentityKeyPair)

            signedDeviceIdentityMsg = b"\x06\x00" + \
                signedDeviceIdentity.details + \
                identityKeyPair.getPublicKey().getPublicKey().getPublicKey()

            if not curve.Curve.verifySignature(
                djbec.DjbECPublicKey(signedDeviceIdentity.accountSignatureKey),
                signedDeviceIdentityMsg,
                signedDeviceIdentity.accountSignature
            ):
                raise AuthenticationFailedError("Failed to verify account signature")

            deviceMessage = b"\x06\x01" + \
                signedDeviceIdentity.details + \
                identityKeyPair.getPublicKey().getPublicKey().getPublicKey() + \
                signedDeviceIdentity.accountSignatureKey

            signedDeviceIdentity.deviceSignature = curve.Curve.calculateSignature(
                identityKeyPair.getPrivateKey(),
                deviceMessage
            )

            conn.authState['me'] = {'jid': jid}
            conn.authState['signalIdentity'] = {
                'identifier': {
                    'name': jid,
                    'deviceId': 0
                },
                'identifierKey': b"\x05" + signedDeviceIdentity.accountSignatureKey
            }
            conn.authState['signedDeviceIdentity'] = {
                'details': signedDeviceIdentity.details,
                'accountSignature': signedDeviceIdentity.accountSignature,
                'accountSignatureKey': signedDeviceIdentity.accountSignatureKey,
                'deviceSignature': signedDeviceIdentity.deviceSignature
            }

            advDeviceIdentity = WAMessage_pb2.ADVDeviceIdentity()
            advDeviceIdentity.ParseFromString(signedDeviceIdentity.details)
            keyIndex = advDeviceIdentity.keyIndex

            accountEnc = WAMessage_pb2.ADVSignedDeviceIdentity()
            accountEnc.details = signedDeviceIdentity.details
            accountEnc.accountSignature = signedDeviceIdentity.accountSignature
            accountEnc.deviceSignature = signedDeviceIdentity.deviceSignature

            conn.sendMessageNode(
                Node("iq", attributes={
                    'to': "@s.whatsapp.net",
                    'type': "result",
                    'id': node['id']
                }, content=Node("pair-device-sign", attributes=None,
                    content=Node("device-identity", attributes={
                        "key-index": str(keyIndex)
                    }, content=accountEnc.SerializeToString())
                ))
            )

            self.log.debug("Auth State: {authState}", authState=conn.authState)
