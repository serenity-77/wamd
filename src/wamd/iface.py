from zope.interface import Interface


class IJsonSerializable(Interface):
    
    def toJson():
        pass

    def populate(self, jsonDict):
        pass
