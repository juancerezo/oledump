from .cdump import cDump
import re

dumplinelength = 16
REGEX_STANDARD = b'[\x09\x20-\x7E]'

def HexDump(data):
    return cDump(data, dumplinelength=dumplinelength).HexDump()

def HexAsciiDump(data, rle=False):
    return cDump(data, dumplinelength=dumplinelength).HexAsciiDump(rle=rle)

def Translate(expression):
    return lambda x: x.decode(expression)

def ExtractStringsASCII(data):
    regex = REGEX_STANDARD + b'{%d,}'
    return re.findall(regex % 4, data)

def ExtractStringsUNICODE(data):
    regex = b'((' + REGEX_STANDARD + b'\x00){%d,})'
    return [foundunicodestring.replace(b'\x00', b'') for foundunicodestring, dummy in re.findall(regex % 4, data)]

def ExtractStrings(data):
    return ExtractStringsASCII(data) + ExtractStringsUNICODE(data)

def DumpFunctionStrings(data):
    return b''.join([extractedstring + b'\n' for extractedstring in ExtractStrings(data)])