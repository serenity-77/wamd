import os
import binascii
import json
import time

from twisted.python.reflect import qual

from .proto import WAMessage_pb2
from wamd.coder import Node
from wamd.utils import protoMessageToJson



class WhatsAppMessage:

    def __init__(self, **kwargs):
        self._attrs = {}

        if "id" not in kwargs or not kwargs['id']:
            kwargs['id'] = self.generateMessageId()

        if "to" in kwargs and "@" not in kwargs['to']:
            kwargs['to'] = kwargs['to'] + "@s.whatsapp.net"

        if "fromMe" not in kwargs:
            kwargs['fromMe'] = True

        if "messageTimestamp" not in kwargs:
            kwargs['messageTimestamp'] = int(time.time())

        for k, v in kwargs.items():
            self._attrs[k] = v

    def __getitem__(self, item):
        try:
            return self._attrs[item]
        except KeyError:
            return None

    def __setitem__(self, item, value):
        self._attrs[item] = value

    def __delitem__(self, item):
        try:
            del self._attrs[item]
        except KeyError:
            pass

    def toProtobufMessage(self):
        raise NotImplementedError("%s must be implemented in child class" % qual(self.toProtobufMessage))

    _STR_INDENT = "    "
    _TEXT_LIMIT = 50

    def __str__(self):
        t = self.__class__.__name__
        indent = self.__class__._STR_INDENT

        s = "\n<%s>\n{OTHERS}</%s>\n" % (t, t)

        if self['from'] is not None:
            o = "%sFrom: %s\n" % (indent, self['from'])
        else:
            o = "%sTo: %s\n" % (indent, self['to'])

        if self['notify']:
            o += "%sNotify: %s\n" % (indent, self['notify'])

        o += "%sFromMe: %s\n" % (indent, self['fromMe'])

        if self['id'] is not None:
            o += "%sID: %s\n" % (indent, self['id'])

        if self['messageTimestamp']:
            o += "%sMessageTimestamp: %s\n" % (indent, self['messageTimestamp'])

        if self['isRead'] is not None:
            o += "%sIsRead: %s\n" % (indent, self['isRead'])

        if isinstance(self, TextMessage):
            o += "%sConversation: %s\n" % (indent, self['conversation'][:self.__class__._TEXT_LIMIT] + "..." if len(self['conversation']) > self.__class__._TEXT_LIMIT else self['conversation'])

        elif isinstance(self, MediaMessage):
            o += "%sMediaType: %s\n" % (indent, self['mediaType'])
            if self['url'] is not None:
                o += "%sUrl: %s\n" % (indent, self['url'])
            else:
                o += "%sDirectPath: %s\n" % (indent, self['directPath'])
            if self['caption'] is not None:
                o += "%sCaption: %s\n" % (indent, self['caption'][:self.__class__._TEXT_LIMIT] + "..." if len(self['caption']) > self.__class__._TEXT_LIMIT else self['caption'])
            if self['fileName'] is not None:
                o += "%sFileName: %s\n" % (indent, self['filename'])
            if self['title'] is not None:
                o += "%sTitle: %s\n" % (indent, self['title'])

        elif isinstance(self, ExtendedTextMessage):
            if self['text'] is not None:
                o += "%sText: %s\n" % (indent, self['text'])
            if self['matchedText'] is not None:
                o += "%sMatchedText: %s\n" % (indent, self['matchedText'])
            if self['canonicalUrl'] is not None:
                o += "%sCanonicalURL: %s\n" % (indent, self['canonicalUrl'])
            if self['description'] is not None:
                o += "%sDescription: %s\n" % (indent, self['description'][:self.__class__._TEXT_LIMIT] + "..." if len(self['description']) > self.__class__._TEXT_LIMIT else self['description'])
            if self['title'] is not None:
                o += "%sTitle: %s\n" % (indent, self['title'][:self.__class__._TEXT_LIMIT] + "..." if len(self['title']) > self.__class__._TEXT_LIMIT else self['title'])

        elif isinstance(self, UnknownMessage):
            ignoreKeys = "from,to,notify,fromMe,id,messageTimestamp".split(",")
            for k, v in self._attrs.items():
                if k not in ignoreKeys:
                    o += "%s%s: %s\n" % (indent, k.title(), str(v) if not isinstance(v, str) else v)

        return s.format(OTHERS=o)

    @staticmethod
    def generateMessageId():
        return "3EB0" + binascii.hexlify(os.urandom(8)).decode().upper()

    @staticmethod
    def fromMessageProto(messageProto, node=None, isRead=True):
        webMessageInfoProto = messageProto

        if isinstance(webMessageInfoProto, WAMessage_pb2.Message):
            if node is None:
                raise ValueError("Instance of %s required" % (qual(Node)))
            messageKey = WAMessage_pb2.MessageKey()
            messageKey.remoteJid = node['from']
            messageKey.fromMe = False if node['fromMe'] is None else node['fromMe']
            messageKey.id = node['id']
            webMessageInfoProto = WAMessage_pb2.WebMessageInfo()
            webMessageInfoProto.key.MergeFrom(messageKey)
            webMessageInfoProto.message.MergeFrom(messageProto)
            webMessageInfoProto.messageTimestamp = int(node['t'])

        if not isinstance(webMessageInfoProto, WAMessage_pb2.WebMessageInfo):
            raise ValueError("Must be an instance of WAMessage_pb2.WebMessageInfo")

        attributes = {}

        if webMessageInfoProto.key.fromMe:
            attributes['to'] = webMessageInfoProto.key.remoteJid
        else:
            attributes['from'] = webMessageInfoProto.key.remoteJid

        attributes.update({
            'fromMe': webMessageInfoProto.key.fromMe,
            'id': webMessageInfoProto.key.id,
            'messageTimestamp': webMessageInfoProto.messageTimestamp,
            'isRead': isRead
        })

        if node is not None:
            attributes['notify'] = node['notify']
            if node['participant'] is not None:
                attributes['participant'] = node['participant']

        if webMessageInfoProto.HasField("message"):
            if webMessageInfoProto.message.HasField("conversation"):
                attributes['conversation'] = webMessageInfoProto.message.conversation
                cls = TextMessage
            else:
                for messageType, klass in _MESSAGE_TYPE_CLASS_MAPS.items():
                    if webMessageInfoProto.message.HasField(messageType):
                        if klass is not None:
                            messageDict = protoMessageToJson(getattr(webMessageInfoProto.message, messageType))
                            attributes.update(messageDict)
                            cls = klass
                        else:
                            raise NotImplementedError("Message Type %s Not Implemented" % (messageType, ))

        else:
            del attributes['isRead']
            messageDict = protoMessageToJson(webMessageInfoProto)
            for k, v in messageDict.items():
                if k != "key":
                    attributes[k] = v
            cls = UnknownMessage

        return cls(**attributes)

    def __repr__(self):
        return "\n<%s Object at 0x%x %s>\n" % (self.__class__.__name__, id(self), self._attrs.__repr__())



class TextMessage(WhatsAppMessage):

    def toProtobufMessage(self):
        messageProto = WAMessage_pb2.Message()
        messageProto.conversation = self['conversation']
        return messageProto


class MediaMessage(WhatsAppMessage):
    pass

class ExtendedTextMessage(WhatsAppMessage):
    pass


class TemplateMessage(WhatsAppMessage):
    pass


class UnknownMessage(WhatsAppMessage):
    pass



_MESSAGE_TYPE_CLASS_MAPS = {
    'imageMessage': MediaMessage,
    'contactMessage': None,
    'locationMessage': None,
    'extendedTextMessage': ExtendedTextMessage,
    'documentMessage': MediaMessage,
    'audioMessage': MediaMessage,
    'videoMessage': MediaMessage,
    'contactsArrayMessage': None,
    'liveLocationMessage': None,
    'templateMessage': TemplateMessage,
    'stickerMessage': None,
    'groupInviteMessage': None,
    'buttonsMessage': None
}

_SUPPORTED_MEDIA_KEYS = [
    "imageMessage",
    "videoMessage",
    "documentMessage",
    "audioMessage",
    "stickerMessage"
]
