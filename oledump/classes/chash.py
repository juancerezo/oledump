import zlib
import sys

class cHashCRC32():
    def __init__(self):
        self.crc32 = None

    def update(self, data):
        self.crc32 = zlib.crc32(data)

    def hexdigest(self):
        return '%08x' % (self.crc32 & 0xffffffff)

class cHashChecksum8():
    def __init__(self):
        self.sum = 0

    def update(self, data):
        if sys.version_info[0] >= 3:
            self.sum += sum(data)
        else:
            self.sum += sum(map(ord, data))

    def hexdigest(self):
        return '%08x' % (self.sum)
