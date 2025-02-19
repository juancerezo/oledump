from .cplugin import cDecoderParent

class cIdentity(cDecoderParent):
    _name: str = 'Identity function decoder'

    def __init__(self, stream, options):
        self.stream = stream
        self.options = options
        self._available = True

    def available(self):
        return self._available

    def decode(self):
        self._available = False
        return self.stream

    def name(self):
        return self._name