import base64

from twisted.logger import Logger
from axolotl.ecc import curve, djbec

from wamd.coder import Node
from wamd.proto import WAMessage_pb2
from wamd.utils import hmacValidate

from .base import NodeHandler



class IqHandler(NodeHandler):

    log = Logger()

    def handleNode(self, conn, node):
        if node['type'] == "set":
            if not conn._authDone():
                self._handlePairing(conn, node)
        else:
            pending = self.getPendingRequestDeferred(conn, node['id'])
            if pending:
                pending.callback(node)

    def _handlePairing(self, conn, node):
        if node.children[0].tag == "pair-device":
            # TODO
            # reload qr from ref list
            refNodes = node.children[0].getChilds("ref")

            qrInfo = [
                refNodes[0].content,
                base64.b64encode(conn.authState.noiseKey.getPublicKey().getPublicKey()),
                base64.b64encode(conn.authState.identityKey.getPublicKey().getPublicKey().getPublicKey()),
                base64.b64encode(conn.authState.advSecretKey)
            ]

            conn.fire("qr", qrInfo).addErrback(
                lambda f: self.log.error("Handle QR Failure: {failure}", failure=f)
            )

            conn.sendMessageNode(Node(
                "iq", attributes={
                    'to': "@s.whatsapp.net",
                    'type': "result",
                    'id': node['id']
                }))

        elif node.children[0].tag == "pair-success":
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

            signedDeviceIdentityMsg = b"\x06\x00" + \
                signedDeviceIdentity.details + \
                conn.authState.identityKey.getPublicKey().getPublicKey().getPublicKey()

            if not curve.Curve.verifySignature(
                djbec.DjbECPublicKey(signedDeviceIdentity.accountSignatureKey),
                signedDeviceIdentityMsg,
                signedDeviceIdentity.accountSignature
            ):
                raise AuthenticationFailedError("Failed to verify account signature")

            deviceMessage = b"\x06\x01" + \
                signedDeviceIdentity.details + \
                conn.authState.identityKey.getPublicKey().getPublicKey().getPublicKey() + \
                signedDeviceIdentity.accountSignatureKey

            signedDeviceIdentity.deviceSignature = curve.Curve.calculateSignature(
                conn.authState.identityKey.getPrivateKey(),
                deviceMessage
            )

            conn.authState.me = {'jid': jid}
            conn.authState.signalIdentity = {
                'identifier': {
                    'name': jid,
                    'deviceId': 0
                },
                'identifierKey': b"\x05" + signedDeviceIdentity.accountSignatureKey
            }
            conn.authState.signedDeviceIdentity = {
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
