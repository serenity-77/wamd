class Constants:
    WHATSAPP_WEBSOCKET_HOST = "web.whatsapp.com"
    WHATSAPP_WEBSOCKET_PORT = 443
    WHATSAPP_WEBSOCKET_URL = "wss://web.whatsapp.com/ws/chat"
    DEFAULT_USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.122 Safari/537.36"
    DEFAULT_ORIGIN = "https://web.whatsapp.com"
    WHATSAPP_WEB_VERSION = [2, 2136, 9]
    DEFAULT_BROWSER_KIND = ["Linux", "Chrome", "x86_64"]
    BUILD_HASH = "S9Kdc4pc4EJryo21snc5cg=="
    PROLOGUE = bytes([87, 65, 5, 2])
    WHATSAPP_LONG_TERM = bytes([
        20, 35, 117, 87, 77, 10, 88, 113, 102, 170, 231, 30, 190, 81, 100, 55, 196,
        162, 139, 115, 227, 105, 92, 108, 225, 247, 249, 84, 93, 168, 238, 107
    ])
    CERTIFICATE_ISSUER = "WhatsAppLongTerm1"
    MEDIA_HOST = "mmg.whatsapp.net"
    FLAG_COMPRESSED = 0x02
