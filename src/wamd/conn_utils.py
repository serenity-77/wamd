from twisted.internet.defer import inlineCallbacks

from wamd.common import GroupInfo, GroupParticipant
from wamd.iface import IGroupStore


@inlineCallbacks
def addGroupInfo(conn, groupNode):
    groupStore = IGroupStore(conn.authState)

    yield groupStore.storeGroupInfo(GroupInfo(**groupNode.attributes))

    for participant in groupNode.findChilds("participant"):
        p = GroupParticipant(**participant.attributes)
        yield groupStore.storeGroupParticipant(groupNode['id'], p)


def getUsyncDeviceList(usyncNode):
    users = usyncNode.findChild("list").findChilds("user")
    userDevices = {}
    for user in users:
        deviceList = []
        for device in user.findChild("devices").findChild("device-list").findChilds("device"):
            deviceList.append(device['id'])
        userDevices[user['jid']] = deviceList
    return userDevices
