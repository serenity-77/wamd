import sys

class Constants:
    WHATSAPP_WEBSOCKET_HOST = "web.whatsapp.com"
    WHATSAPP_WEBSOCKET_PORT = 443
    WHATSAPP_WEBSOCKET_URL = "wss://web.whatsapp.com/ws/chat"
    DEFAULT_USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36"
    DEFAULT_ORIGIN = "https://web.whatsapp.com"
    WHATSAPP_WEB_VERSION = [2, 2146, 9]
    DEFAULT_BROWSER_KIND = ["NusaSMS", "Chrome", "x86_64"]
    BUILD_HASH = "S9Kdc4pc4EJryo21snc5cg=="
    PROLOGUE = bytes([87, 65, 5, 2])
    WHATSAPP_LONG_TERM = bytes([
        20, 35, 117, 87, 77, 10, 88, 113, 102, 170, 231, 30, 190, 81, 100, 55, 196,
        162, 139, 115, 227, 105, 92, 108, 225, 247, 249, 84, 93, 168, 238, 107
    ])
    CERTIFICATE_ISSUER = "WhatsAppLongTerm1"
    MEDIA_HOST = "mmg.whatsapp.net"
    FLAG_COMPRESSED = 0x02
    S_WHATSAPP_NET = "@s.whatsapp.net"
    G_US = "@g.us"
    MAX_PREKEYS_UPLOAD = 30
    MESSAGE_STORE_RETRY_PREFIX = "FOR_RETRY-"

    IS_LITTLE_ENDIAN = sys.byteorder == "little"

    RECEIPT_TYPE_DELIVERED = 2
    RECEIPT_TYPE_READ = 3

    IMAGE_MIME_TYPES = [
        "image/jpeg",
        "image/png",
        "image/jpg",
        "image/webp",
        "image/tiff",
        "image/gif",
        "image/bmp"
    ]

    VIDEO_MIME_TYPES = [
        "video/mp4",
        "video/3gpp",
        "video/3gp",
        "video/mpeg",
        "video/ogg",
        "video/x-msvideo"
    ]

    AUDIO_MIME_TYPES = [
        "audio/mpeg",
        "audio/ogg",
        "audio/opus",
        "audio/wav",
        "audio/x-wav",
        "audio/webm",
        "application/ogg",
        "audio/ogg; codecs=opus"
    ]

    DOCUMENT_MIME_TYPES = [
        "application/pdf",
        "application/zip",
        "application/msword",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "text/csv",
        "text/plain",
        "application/x-tar",
        "application/vnd.ms-excel",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "application/x-7z-compressed",
        "application/x-bzip",
        "application/x-bzip2"
    ]

    MEDIA_INFO_KEYS = {
        "image": b"WhatsApp Image Keys",
        "video": b"WhatsApp Video Keys",
        "audio": b"WhatsApp Audio Keys",
        "document": b"WhatsApp Document Keys",
        "history": b"WhatsApp History Keys"
    }
