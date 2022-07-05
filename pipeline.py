import json
from typing import Union
import redis

RD = redis.Redis()


def process_key(data: dict) -> bool:
    """ process key
    save data into db or update
    :param data: type dict
    :return save data return True
    """
    key = data["entity_id"]
    return save_update_key(key, data)


def exist_key(key: str) -> bool:
    """ is key exist
    :param str key: type string
    :return: if key exist return True else false
    """
    if RD.exists(key): return True
    return False


def get_key(key: str) -> dict:
    """ get key and return dict
    :param str key: type string
    :return: dict
    """
    return json.loads(RD.get(key))


def get_key_multi(key: str) -> list:
    """ get key and return list
    :param str key: type string example header*
    :return: dict
    """
    return RD.keys(key)


def delete_key(key: str) -> None:
    """ delete key
    :param str key: type string
    """
    RD.delete(key)


def save_update_key(key: str, data: Union[list, dict]) -> bool:
    """ save data to redis
    :param key: entity id telegram
    :param str data: type json
    :return: if save into db return True else false
    """
    return RD.set(key, json.dumps(data))
