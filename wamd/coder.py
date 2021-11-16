import sys
import binascii

import xml.etree.cElementTree as ET
from xml.dom import minidom

from io import BytesIO

from .tokendict import WASingleByteTokens, WADoubleByteTokens
from .errors import StreamEndError

class WATags:
    LIST_EMPTY      = 0
    STREAM_END      = 2
    DICTIONARY_0    = 236
    DICTIONARY_1    = 237
    DICTIONARY_2    = 238
    DICTIONARY_3    = 239
    LIST_8          = 248
    LIST_16         = 249
    JID_PAIR        = 250
    HEX_8           = 251
    BINARY_8        = 252
    BINARY_20       = 253
    BINARY_32       = 254
    NIBBLE_8        = 255
    SINGLE_BYTE_MAX = 256
    PACKED_MAX      = 254

    @staticmethod
    def get(str):
        return WATags.__dict__[str]


_IS_LITTLE_ENDIAN = sys.byteorder == "little"


class WABinaryWriter:

    # Copied From Yowsup
    # https://github.com/tgalal/yowsup/blob/master/yowsup/layers/coder/encoder.py

    def __init__(self, node):
        self._node = node
        self._data = []
        self._writeInternal()

    def getData(self):
        data = bytes(self._data)
        self._data = []
        return data

    def _writeInternal(self, node=None):
        if node is None:
            node = self._node

        if node is None:
            return

        if not isinstance(self._node, Node):
            raise ValueError("invalid node")

        numAttributes = getNumValidKeys(node.attributes) if node.attributes is not None else 0

        self._writeListStart(2*numAttributes + 1 + (1 if node.hasContent() else 0))
        self._writeString(node.tag)
        self._writeAttributes(node.attributes)
        self._writeChildren(node.content if node.content is not None else node.children)

    def _writeChildren(self, children):
        if children is None:
            return

        if isinstance(children, str):
            self._writeString(children, True)
        elif isinstance(children, bytes):
            self._writeBytes(children)
        else:
            if not isinstance(children, list):
                raise ValueError("invalid children")
            self._writeListStart(len(children))
            for c in children:
                self._writeInternal(c)

    def _writeAttributes(self, attributes):
        if attributes is not None:
            for key, value in attributes.items():
                self._writeString(key)
                self._writeString(value, True)

    def _writeBytes(self, bytes_, packed = False):
        bytes__ = []
        for b in bytes_:
            if type(b) is int:
                bytes__.append(b)
            else:
                bytes__.append(ord(b))

        size = len(bytes__)
        toWrite = bytes__
        if size >= 0x100000:
            self._data.append(254)
            self._writeInt31(size)
        elif size >= 0x100:
            self._data.append(253)
            self._writeInt20(size)
        else:
            r = None
            if packed:
                if size < 128:
                    r = self._tryPackAndWriteHeader(251, bytes__)
                    if r is None:
                        r = self._tryPackAndWriteHeader(255, bytes__)

            if r is None:
                if size:
                    self._data.append(252)
                self._writeInt8(size)
            else:
                toWrite = r

        self._data.extend(toWrite)

    def _writeInt8(self, v):
        self._data.append(v & 0xFF)

    def _writeInt16(self, v):
        self._data.append((v & 0xFF00) >> 8)
        self._data.append((v & 0xFF) >> 0)

    def _writeInt20(self, v):
        self._data.append((0xF0000 & v) >> 16)
        self._data.append((0xFF00 & v) >> 8)
        self._data.append((v & 0xFF) >> 0)

    def _writeInt24(self, v):
        self._data.append((v & 0xFF0000) >> 16)
        self._data.append((v & 0xFF00) >> 8)
        self._data.append((v & 0xFF) >> 0)

    def _writeInt31(self, v):
        self._data.append((0x7F000000 & v) >> 24)
        self._data.append((0xFF0000 & v) >> 16)
        self._data.append((0xFF00 & v) >> 8)
        self._data.append((v & 0xFF) >> 0)

    def _writeListStart(self, i):
        if i == 0:
            self._data.append(0)
        elif i < 256:
            self._data.append(248)
            self._writeInt8(i)
        else:
            self._data.append(249)
            self._writeInt16(i)

    def _writeToken(self, token):
        if token <= 255 and token >=0:
            self._data.append(token)
        else:
            raise ValueError("Invalid token: %s" % token)


    def _writeString(self, tag, packed = False):
        tok = self._getIndex(tag)
        if tok:
            index, secondary = tok
            if not secondary:
                self._writeToken(index)
            else:
                quotient = index // 256
                if quotient == 0:
                    double_byte_token = 236
                elif quotient == 1:
                    double_byte_token = 237
                elif quotient == 2:
                    double_byte_token = 238
                elif quotient == 3:
                    double_byte_token = 239
                else:
                    raise ValueError("Double byte dictionary token out of range")

                self._writeToken(double_byte_token)
                self._writeToken(index % 256)
        else:
            try:
                user, server = tag.split("@", 1)
            except ValueError:
                self._writeBytes(self._encodeString(tag), packed)
            else:
                if server == "c.us":
                    server = "s.whatsapp.net"
                if server == "s.whatsapp.net":
                    self._writeJid(user, server)
                else:
                    self._writeBytes(self.encodeString(tag), packed)

    def _encodeString(self, s):
        if isinstance(s, str):
            return s.encode()
        return s

    def _writeJid(self, user, server):
        self._data.append(250)
        if user is None:
            user = ""
        self._writeString(user, True)
        self._writeString(server)

    def _tryPackAndWriteHeader(self, v, headerData):
        size = len(headerData)
        if size >= 128:
            return None

        arr = [0] * int((size + 1) / 2)
        for i in range(0, size):
            packByte = self._packByte(v, headerData[i])
            if packByte == -1:
                arr = []
                break
            n2 = int(i / 2)
            arr[n2] |= (packByte << 4 * (1 - i % 2))
        if len(arr) > 0:
            if size % 2 == 1:
                arr[-1] |= 15 #0x0F
            self._data.append(v)
            self._writeInt8(size %2 << 7 | len(arr))
            return arr

        return None

    def _packByte(self, v, n2):
        if v == 251:
            return self._packHex(n2)
        if v == 255:
            return self._packNibble(n2)
        return -1

    def _packHex(self, n):
        if n in range(48, 58):
            return n - 48
        if n in range(65, 71):
            return 10 + (n - 65)
        return -1

    def _packNibble(self, n):
        if n in (45, 46):
            return 10 + (n - 45)

        if n in range(48, 58):
            return n - 48

        return -1

    def _getIndex(self, token):
        if token in WASingleByteTokens:
            return (WASingleByteTokens.index(token), False)
        elif token in WADoubleByteTokens:
            return (WADoubleByteTokens.index(token), True)
        return None


class WABinaryReader:

    # Copied From sigalor
    # https://github.com/sigalor/whatsapp-web-reveng/blob/master/backend/whatsapp_binary_reader.py

    def __init__(self, data):
        self.data = data
        self.index = 0

    def checkEOS(self, length):
        if self.index + length > len(self.data):
            raise EOFError("end of stream reached")

    def readByte(self):
        self.checkEOS(1)
        ret = self.data[self.index]
        self.index += 1
        return ret

    def readIntN(self, n, littleEndian=False):
        self.checkEOS(n)
        ret = 0
        for i in range(n):
            currShift = i if littleEndian else n-1-i
            ret |= self.data[self.index + i] << (currShift*8)
        self.index += n
        return ret

    def readInt16(self, littleEndian=False):
        return self.readIntN(2, littleEndian)

    def readInt20(self):
        self.checkEOS(3)
        ret = ((self.data[self.index] & 15) << 16) + (self.data[self.index+1] << 8) + self.data[self.index+2]
        self.index += 3
        return ret

    def readInt32(self, littleEndian=False):
        return self.readIntN(4, littleEndian)

    def readInt64(self, littleEndian=False):
        return self.readIntN(8, littleEndian)

    def readPacked8(self, tag):
        startByte = self.readByte()
        ret = ""
        for i in range(startByte & 127):
            currByte = self.readByte()
            ret += self.unpackByte(tag, (currByte & 0xF0) >> 4) + self.unpackByte(tag, currByte & 0x0F)
        if (startByte >> 7) != 0:
            ret = ret[:len(ret)-1]
        return ret

    def unpackByte(self, tag, value):
        if tag == WATags.NIBBLE_8:
            return self.unpackNibble(value)
        elif tag == WATags.HEX_8:
            return self.unpackHex(value)

    def unpackNibble(self, value):
        if value >= 0 and value <= 9:
            return chr(ord('0') + value)
        elif value == 10:
            return "-"
        elif value == 11:
            return "."
        elif value == 15:
            return "\0"
        raise ValueError("invalid nibble to unpack: " + value)

    def unpackHex(self, value):
        if value < 0 or value > 15:
            raise ValueError("invalid hex to unpack: " + str(value))
        if value < 10:
            return chr(ord('0') + value)
        else:
            return chr(ord('A') + value - 10)

    def readRangedVarInt(self, minVal, maxVal, desc="unknown"):
        ret = self.readVarInt()
        if ret < minVal or ret >= maxVal:
            raise ValueError("varint for " + desc + " is out of bounds: " + str(ret))
        return ret


    def isListTag(self, tag):
        return tag == WATags.LIST_EMPTY or tag == WATags.LIST_8 or tag == WATags.LIST_16

    def readListSize(self, tag):
        if(tag == WATags.LIST_EMPTY):
            return 0
        elif(tag == WATags.LIST_8):
            return self.readByte()
        elif(tag == WATags.LIST_16):
            return self.readInt16()
        raise ValueError("invalid tag for list size: " + str(tag))

    def readString(self, tag):
        if tag >= 3 and tag <= 235:
            token = self.getToken(tag)
            return token

        if tag == WATags.DICTIONARY_0 or tag == WATags.DICTIONARY_1 or tag == WATags.DICTIONARY_2 or tag == WATags.DICTIONARY_3:
            return self.getTokenDouble(tag - WATags.DICTIONARY_0, self.readByte())
        elif tag == WATags.LIST_EMPTY:
            return None
        elif tag == WATags.BINARY_8:
            return self.readStringFromChars(self.readByte())
        elif tag == WATags.BINARY_20:
            return self.readStringFromChars(self.readInt20())
        elif tag == WATags.BINARY_32:
            return self.readStringFromChars(self.readInt32())
        elif tag == WATags.JID_PAIR:
            user = self.readString(self.readByte())
            if user is None:
                user = ""
            if isinstance(user, bytes):
                user = user.decode()
            server = self.readString(self.readByte())
            if not server:
                raise ValueError("invalid jid pair: %s, %s" % (user, server, ))
            if isinstance(server, bytes):
                server = server.decode()
            return "%s@%s" % (user, server, )
        elif tag == WATags.NIBBLE_8 or tag == WATags.HEX_8:
            return self.readPacked8(tag)
        elif tag == 247:
            agent = self.readByte()
            device = self.readByte()
            user = self.readString(self.readByte())
            if user is None:
                user = ""
            return buildJid(user, "s.whatsapp.net", agent, device)
        else:
            raise ValueError("invalid string with tag " + str(tag))

    def readStringFromChars(self, length):
        self.checkEOS(length)
        ret = self.data[self.index:self.index+length]
        self.index += length
        return ret.decode()

    def readAttributes(self, n):
        ret = {}
        if n == 0:
            return
        for i in range(n):
            index = self.readString(self.readByte())
            ret[index] = self.readString(self.readByte())
        return ret

    def readList(self, tag):
        ret = []
        for i in range(self.readListSize(tag)):
            ret.append(self.readNode())
        return ret

    def readNode(self):
        listSize = self.readListSize(self.readByte())
        descrTag = self.readByte()
        if descrTag == WATags.STREAM_END:
            raise StreamEndError("unexpected stream end")
        descr = self.readString(descrTag)
        if listSize == 0 or not descr:
            raise ValueError("invalid node")
        attrs = self.readAttributes((listSize-1) >> 1)
        if listSize % 2 == 1:
            return Node(descr, attributes=attrs)

        tag = self.readByte()
        if self.isListTag(tag):
            content = self.readList(tag)
        elif tag == WATags.BINARY_8:
            content = self.readBytes(self.readByte())
        elif tag == WATags.BINARY_20:
            content = self.readBytes(self.readInt20())
        elif tag == WATags.BINARY_32:
            content = self.readBytes(self.readInt32())
        else:
            content = self.readString(tag)

        if isinstance(content, list):
            node = Node(descr, attributes=attrs)
            for child in content:
                node.addChild(child)
            return node

        return Node(descr, attributes=attrs, content=content)

    def readBytes(self, n):
        bytes = self.data[self.index:self.index+n]
        self.index += n
        return bytes

    def getToken(self, index):
        if index < 3 or index >= len(WASingleByteTokens):
            raise ValueError("invalid token index: " + str(index))
        return WASingleByteTokens[index]

    def getTokenDouble(self, index1, index2):
        n = 256 * index1 + index2
        if n < 0 or n >= len(WADoubleByteTokens):
            raise ValueError("invalid token index: " + str(n))
        return WADoubleByteTokens[n]


# Based on yowsup ProtocolTreeNode
class Node:

    def __init__(self, tag, attributes=None, content=None):
        self.tag = tag
        self.attributes = attributes

        if isinstance(content, Node):
            content = [content]

        if isinstance(content, list):
            self.children = content
            self.content = None
        else:
            self.content = content
            self.children = []

    def addChild(self, node):
        self.children.append(node)

    def getAllChildren(self):
        return self.children[:]

    def __getitem__(self, key):
        if not self.attributes:
            return None
        try:
            return self.attributes[key]
        except KeyError:
            return None

    def __setitem__(self, key, value):
        if self.attributes is None:
            self.attributes = {}
        self.attributes[key] = value

    def findChild(self, tag):
        for child in self.children:
            if child.tag == tag:
                return child
        return None

    def getChilds(self, tag):
        results = []
        for child in self.children:
            if child.tag == tag:
                results.append(child)
        return results

    getChild = findChild

    def hasContent(self):
        return self.content is not Node or self.children is not None

    def getContent(self):
        return self.content

    def _createRootElement(self):
        attrs = {}
        if self.attributes is not None:
            for k, v in self.attributes.items():
                if not isinstance(v, str):
                    v = str(v)
                attrs[k] = v

        tagElement = ET.Element(self.tag, **attrs)

        if self.content is not None:
            content = self.content
            if isinstance(content, bytes):
                content = binascii.hexlify(content).decode()
            tagElement.text = content

        elif self.children is not None:
            for children in self.children:
                tagElement.append(children._createRootElement())

        return tagElement

    def toXmlTree(self):
        rootElement = self._createRootElement()
        return ET.ElementTree(rootElement)

    _XML_STRING_INDENT = "    "

    # Fineeee!!! I'll do it myself
    def _toXmlString(self, indent=""):
        s = "%s<%s" % (indent, self.tag)

        if self.attributes is not None:
            for k, v in self.attributes.items():
                if not isinstance(v, str):
                    v = str(v)
                s += " %s=\"%s\"" % (k, v)

        s += ">"

        if self.content is not None:
            content = self.content
            if isinstance(content, bytes):
                content = binascii.hexlify(content).decode()
            s += content

        elif self.children is not None:
            indent2 = indent + self.__class__._XML_STRING_INDENT
            for children in self.children:
                s += "\n%s" % (children._toXmlString(indent=indent2))

        s += "%s%s</%s>" % ("\n" if self.children else "", indent if self.children else "", self.tag)

        return s

    def __str__(self):
        return self._toXmlString()


def encodeInt(value, length):
    t = []
    for i in range(length):
        shiftLength = i if not _IS_LITTLE_ENDIAN else length - (i + 1)
        t.append((value >> (shiftLength * 8)) & 0xFF)
    return bytes(t)


def decodeInt(value, length):
    if not value:
        return 0
    v = value[:length]
    if _IS_LITTLE_ENDIAN:
        v = v[::-1]
    r = 0
    for i in range(length):
        r |= (v[i] << (i * 8))
    return r

def getNumValidKeys(obj):
	return len(list(filter(lambda x: obj[x] is not None, list(obj.keys()))))


def buildJid(user, server, agent, device):
    if not server:
        raise ValueError("Server Required")
    if user is None:
        user = ""
    jid = user
    if agent:
        jid = jid + "_" + str(agent)
    if device:
        jid = jid + ":" + str(device)
    jid = jid + "@" + server
    return jid


_EMTPY_JID = (None, None, None, None)


def splitJid(jid):
    if not jid:
        return _EMTPY_JID

    try:
        u, server = jid.split("@")
    except ValueError:
        raise ValueError("Unsupported jid format: %s" % (jid, ))

    try:
        userAgent, device = u.split(":")
    except ValueError:
        return (u, None, None, server)

    user, agent = _splitUserAgent(userAgent)
    return (user, agent, device, server)


def _splitUserAgent(userAgent):
    try:
        user, agent = userAgent.split("_")
    except ValueError:
        return (userAgent, None)

    return (user, agent)
