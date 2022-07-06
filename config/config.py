from os import environ

from dotenv import load_dotenv

load_dotenv()


class Config:
    ######################### Application Config ######################################
    DEBUG = bool(int(environ.get("WA_DEBUG", "0")))
    ENV = environ.get("WA_ENV", "production")
    ######################### Rabbitmq Config #################################
    USER_RABBIT = environ.get("WA_USER_RABBIT", None)
    PASS_RABBIT = environ.get("WA_PASS_RABBIT", None)
    URL_RABBIT = environ.get("WA_URL_RABBIT", None)
    VIRTUAL_HOST_RABBIT = environ.get("WA_VIRTUAL_HOST_RABBIT", None)
    ROUTING_KEY_RABBIT = environ.get("WA_ROUTING_KEY_RABBIT", None)
