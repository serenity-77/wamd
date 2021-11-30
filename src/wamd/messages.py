import os
import binascii
import json
import time

from twisted.python.reflect import qual

from .proto import WAMessage_pb2
from wamd.coder import Node
from wamd.utils import (
    protoMessageToJson,
    mediaTypeFromMime,
    jsonToProtoMessage,
    isGroupJid
)


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

        if self['participant']:
            o += "%sParticipant: %s\n" % (indent, self['participant'])

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
            o += "%sMime: %s\n" % (indent, self['mimetype'])
            if self['url'] is not None:
                o += "%sUrl: %s\n" % (indent, self['url'])
            else:
                o += "%sDirectPath: %s\n" % (indent, self['directPath'])
            if self['caption'] is not None and self['mediaType'] in ["image", "video"]:
                o += "%sCaption: %s\n" % (indent, self['caption'][:self.__class__._TEXT_LIMIT] + "..." if len(self['caption']) > self.__class__._TEXT_LIMIT else self['caption'])
            if self['fileName'] is not None:
                o += "%sFileName: %s\n" % (indent, self['fileName'])
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

        elif isinstance(self, ProtocolMessage):
            ignoreKeys = "from,to,notify,fromMe,id,messageTimestamp,isRead,participant".split(",")
            for k, v in self._attrs.items():
                if k not in ignoreKeys:
                    o += "%s%s: %s\n" % (indent, k.title(), str(v) if not isinstance(v, str) else v)

        return s.format(OTHERS=o)

    @staticmethod
    def generateMessageId():
        return "3EB0" + binascii.hexlify(os.urandom(8)).decode().upper()

    @staticmethod
    def fromWebMessageInfoProto(webMessageInfoProto, isRead=True):
        if not isinstance(webMessageInfoProto, WAMessage_pb2.WebMessageInfo):
            raise ValueError("Must be an instance of %s" % qual(WAMessage_pb2.WebMessageInfo))

        messageDict = protoMessageToJson(webMessageInfoProto)
        messageKey = messageDict['key']
        del messageDict['key']

        try:
            message = messageDict['message']
            del messageDict['message']
        except KeyError:
            message = None

        attributes = {}

        if messageKey['fromMe']:
            attributes['to'] = messageKey['remoteJid']
        else:
            attributes['from'] = messageKey['remoteJid']

        attributes.update({
            'fromMe': messageKey['fromMe'],
            'id': messageKey['id'],
            'messageTimestamp': messageDict['messageTimestamp'],
            'isRead': isRead
        })

        attributes.update(messageDict)

        if message is not None:
            if "conversation" in message:
                attributes['conversation'] = message['conversation']
                cls = TextMessage
            else:
                for messageType, klass in _MESSAGE_TYPE_CLASS_MAPS.items():
                    if messageType in message:
                        if klass is not None:
                            attributes.update(message[messageType])
                            if messageType in _SUPPORTED_MEDIA_KEYS:
                                attributes['mediaType'] = mediaTypeFromMime(message[messageType]['mimetype'])
                            cls = klass
                        else:
                            raise NotImplementedError("Message Type [%s] Not Implemented" % (messageType, ))

        else:
            cls = ProtocolMessage

        return cls(**attributes)

    def __repr__(self):
        return "\n<%s Object at 0x%x %s>\n" % (self.__class__.__name__, id(self), self._attrs.__repr__())



class TextMessage(WhatsAppMessage):

    def toProtobufMessage(self):
        messageProto = WAMessage_pb2.Message()
        messageProto.conversation = self['conversation']
        return messageProto


class MediaMessage(WhatsAppMessage):

    def toProtobufMessage(self):
        mediaType = self['mediaType']

        if mediaType == "image":
            protoFactory = WAMessage_pb2.ImageMessage
            messageProtoKey = "imageMessage"
        elif mediaType == "document":
            protoFactory = WAMessage_pb2.DocumentMessage
            messageProtoKey = "documentMessage"
        elif mediaType == "video":
            protoFactory = WAMessage_pb2.VideoMessage
            messageProtoKey = "videoMessage"
        elif mediaType == "audio":
            protoFactory = WAMessage_pb2.AudioMessage
            messageProtoKey = "audioMessage"

        mediaProto = jsonToProtoMessage(self._attrs, protoFactory)
        messageProto = WAMessage_pb2.Message()
        getattr(messageProto, messageProtoKey).MergeFrom(mediaProto)

        return messageProto


class StickerMessage(MediaMessage):
    pass


class ExtendedTextMessage(WhatsAppMessage):
    pass


class TemplateMessage(WhatsAppMessage):
    pass


class ProtocolMessage(WhatsAppMessage):
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
    'stickerMessage': StickerMessage,
    'groupInviteMessage': None,
    'buttonsMessage': None,
    'templateButtonReplyMessage': None
}

_SUPPORTED_MEDIA_KEYS = [
    "imageMessage",
    "videoMessage",
    "documentMessage",
    "audioMessage",
    "stickerMessage"
]
