import optparse
import sys
import math
import os
import binascii
import xml.dom.minidom
import zlib
import hashlib
import textwrap
import re
import string
import codecs
import json
import struct
import datetime
import collections

class cStruct(object):
    def __init__(self, data):
        self.data = data
        self.originaldata = data

    def UnpackSub(self, format):
        if format.endswith('z'):
            format = format[:-1]
            sz = True
        else:
            sz = False
        formatsize = struct.calcsize(format)
        if len(self.data) < formatsize:
            raise Exception('Not enough data')
        tounpack = self.data[:formatsize]
        self.data = self.data[formatsize:]
        result = struct.unpack(format, tounpack)
        if sz:
            result = result + (self.GetString0(), )
        return result

    def Unpack(self, format):
        result = self.UnpackSub(format)
        if len(result) == 1:
            return result[0]
        else:
            return result

    def UnpackNamedtuple(self, format, typename, field_names):
        namedTuple = collections.namedtuple(typename, field_names)
        result = self.UnpackSub(format)
        return namedTuple(*result)

    def Truncate(self, length):
        self.data = self.data[:length]

    def GetBytes(self, length=None):
        if length == None:
            length = len(self.data)
        result = self.data[:length]
        if len(result) < length:
            raise Exception('Not enough data')
        self.data = self.data[length:]
        return result

    def GetString(self, format):
        stringLength = self.Unpack(format)
        return self.GetBytes(stringLength)

    def Length(self):
        return len(self.data)

    def GetString0(self):
        position = self.data.find(b'\x00')
        if position == -1:
            raise Exception('Missing NUL byte')
        result = self.data[:position]
        self.data = self.data[position + 1:]
        return result