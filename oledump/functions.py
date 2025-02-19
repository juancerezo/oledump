import sys
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

from .ansi_code_pages import ANSI_CODE_PAGES

__all__ = [
    "C2BIP3",
    "C2SIP3",
    "CIC",
    "IFF",
    "P23Ord",
    "P23Chr",
    "File2String",
]

#Convert 2 Bytes If Python 3
def C2BIP3(string):
    if sys.version_info[0] > 2:
        if type(string) == bytes:
            return string
        else:
            return bytes([ord(x) for x in string])
    else:
        return string

#Convert 2 String If Python 3
def C2SIP3(string):
    if sys.version_info[0] > 2:
        if type(string) == bytes:
            return ''.join([chr(x) for x in string])
        else:
            return string
    else:
        return string

# CIC: Call If Callable
def CIC(expression):
    if callable(expression):
        return expression()
    else:
        return expression

# IFF: IF Function
def IFF(expression, valueTrue, valueFalse):
    if expression:
        return CIC(valueTrue)
    else:
        return CIC(valueFalse)

def P23Ord(value):
    if type(value) == int:
        return value
    else:
        return ord(value)

def P23Chr(value):
    if type(value) == int:
        return chr(value)
    else:
        return value

def File2String(filename):
    try:
        f = open(filename, 'rb')
    except:
        return None
    try:
        return f.read()
    except:
        return None
    finally:
        f.close()

#Fix for http://bugs.python.org/issue11395
def StdoutWriteChunked(data):
    if sys.version_info[0] > 2:
        sys.stdout.buffer.write(C2BIP3(data))
    else:
        while data != '':
            sys.stdout.write(data[0:10000])
            try:
                sys.stdout.flush()
            except IOError:
                return
            data = data[10000:]

def PrintableName(fname, orphan=0):
    if orphan == 1:
        return 'Orphan: ' + repr(fname)
    else:
        return repr('/'.join(fname))

def ParseTokenSequence(data):
    flags = P23Ord(data[0])
    data = data[1:]
    result = []
    for mask in [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80]:
        if len(data) > 0:
            if flags & mask:
                result.append(data[0:2])
                data = data[2:]
            else:
                result.append(data[0])
                data = data[1:]
    return result, data

def OffsetBits(data):
    numberOfBits = int(math.ceil(math.log(len(data), 2)))
    if numberOfBits < 4:
        numberOfBits = 4
    elif numberOfBits > 12:
        numberOfBits = 12
    return numberOfBits

def Bin(number):
    result = bin(number)[2:]
    while len(result) < 16:
        result = '0' + result
    return result

def DecompressChunk(compressedChunk):
    if len(compressedChunk) < 2:
        return None, None
    header = P23Ord(compressedChunk[0]) + P23Ord(compressedChunk[1]) * 0x100
    size = (header & 0x0FFF) + 3
    flagCompressed = header & 0x8000
    data = compressedChunk[2:2 + size - 2]

    if flagCompressed == 0:
        return data.decode(errors='ignore'), compressedChunk[size:]

    decompressedChunk = ''
    while len(data) != 0:
        tokens, data = ParseTokenSequence(data)
        for token in tokens:
            if type(token) == int:
                decompressedChunk += chr(token)
            elif len(token) == 1:
                decompressedChunk += token
            else:
                if decompressedChunk == '':
                    return None, None
                numberOfOffsetBits = OffsetBits(decompressedChunk)
                copyToken = P23Ord(token[0]) + P23Ord(token[1]) * 0x100
                offset = 1 + (copyToken >> (16 - numberOfOffsetBits))
                length = 3 + (((copyToken << numberOfOffsetBits) & 0xFFFF) >> numberOfOffsetBits)
                copy = decompressedChunk[-offset:]
                copy = copy[0:length]
                lengthCopy = len(copy)
                while length > lengthCopy: #a#
                    if length - lengthCopy >= lengthCopy:
                        copy += copy[0:lengthCopy]
                        length -= lengthCopy
                    else:
                        copy += copy[0:length - lengthCopy]
                        length -= length - lengthCopy
                decompressedChunk += copy
    return decompressedChunk, compressedChunk[size:]

def Decompress(compressedData, replace=True):
    if P23Ord(compressedData[0]) != 1:
        return (False, None)
    remainder = compressedData[1:]
    decompressed = ''
    while len(remainder) != 0:
        decompressedChunk, remainder = DecompressChunk(remainder)
        if decompressedChunk == None:
            return (False, decompressed)
        decompressed += decompressedChunk
    if replace:
        return (True, decompressed.replace('\r\n', '\n'))
    else:
        return (True, decompressed)

def FindCompression(data):
    return data.find(b'\x00Attribut\x00e ')

def SearchAndDecompressSub(data):
    position = FindCompression(data)
    if position == -1:
        return (False, '')
    else:
        compressedData = data[position - 3:]
    return Decompress(compressedData)

def SkipAttributes(text):
    oAttribute = re.compile('^Attribute VB_.+? = [^\n]+\n')
    while True:
        oMatch = oAttribute.match(text)
        if oMatch == None:
            break
        text = text[len(oMatch.group()):]
    return text

def SearchAndDecompress(data, ifError='Error: unable to decompress\n', skipAttributes=False):
    result, decompress = SearchAndDecompressSub(data)
    if result or ifError == None:
        if skipAttributes:
            return SkipAttributes(decompress)
        else:
            return decompress
    else:
        return ifError

def ReadWORD(data):
    if len(data) < 2:
        return None, None
    return P23Ord(data[0]) + P23Ord(data[1]) *0x100, data[2:]

def ReadDWORD(data):
    if len(data) < 4:
        return None, None
    return P23Ord(data[0]) + P23Ord(data[1]) *0x100 + P23Ord(data[2]) *0x10000 + P23Ord(data[3]) *0x1000000, data[4:]

def ReadNullTerminatedString(data):
    position = data.find(b'\x00')
    if position == -1:
        return None, None
    return data[:position], data[position + 1:]

def ExtractOle10Native(data):
    size, data = ReadDWORD(data)
    if size == None:
        return []
    dummy, data = ReadWORD(data)
    if dummy == None:
        return []
    filename, data = ReadNullTerminatedString(data)
    if filename == None:
        return []
    pathname, data = ReadNullTerminatedString(data)
    if pathname == None:
        return []
    dummy, data = ReadDWORD(data)
    if dummy == None:
        return []
    dummy, data = ReadDWORD(data)
    if dummy == None:
        return []
    temppathname, data = ReadNullTerminatedString(data)
    if temppathname == None:
        return []
    sizeEmbedded, data = ReadDWORD(data)
    if sizeEmbedded == None:
        return []
    if len(data) < sizeEmbedded:
        return []

    return [filename, pathname, temppathname, data[:sizeEmbedded]]

def Extract(data):
    result = ExtractOle10Native(data)
    if result == []:
        return 'Error: extraction failed'
    return result[3]

def GenerateMAGIC(data):
    return binascii.b2a_hex(data) + b' ' + b''.join([IFF(P23Ord(c) >= 32 and P23Ord(c) < 127, C2BIP3(P23Chr(c)), b'.') for c in data])

def Info(data):
    result = ExtractOle10Native(data)
    if result == []:
        return 'Error: extraction failed'
    return 'String 1: %s\nString 2: %s\nString 3: %s\nSize embedded file: %d\nMD5 embedded file: %s\nSHA256 embedded file: %s\nMAGIC:  %s\nHeader: %s\n' % (result[0], result[1], result[2], len(result[3]), hashlib.md5(result[3]).hexdigest(), hashlib.sha256(result[3]).hexdigest(), GenerateMAGIC(result[3][0:4]), GenerateMAGIC(result[3][0:16]))

def IfWIN32SetBinary(io):
    if sys.platform == 'win32':
        import msvcrt
        msvcrt.setmode(io.fileno(), os.O_BINARY)

def File2Strings(filename):
    try:
        f = open(filename, 'r')
    except:
        return None
    try:
        return map(lambda line:line.rstrip('\n'), f.readlines())
    except:
        return None
    finally:
        f.close()

def ProcessAt(argument):
    if argument.startswith('@'):
        strings = File2Strings(argument[1:])
        if strings == None:
            raise Exception('Error reading %s' % argument)
        else:
            return strings
    else:
        return [argument]


def ExpandFilenameArguments(filenames):
    return list(collections.OrderedDict.fromkeys(sum(map(glob.glob, sum(map(ProcessAt, filenames), [])), [])))

def LookupCodepage(codepage):
    if codepage in ANSI_CODE_PAGES:
        return ANSI_CODE_PAGES[codepage]
    else:
        return ''

def MyRepr(stringArg):
    stringRepr = repr(stringArg)
    if "'" + stringArg + "'" != stringRepr:
        return stringRepr
    else:
        return stringArg

def FindAll(data, sub):
    result = []
    start = 0
    while True:
        position = data.find(sub, start)
        if position == -1:
            return result
        result.append(position)
        start = position + 1

def HeuristicZlibDecompress(data):
    for position in FindAll(data, b'\x78'):
        try:
            return zlib.decompress(data[position:])
        except:
            pass
    return data

def HeuristicDecompress(data):
    status, decompresseddata = Decompress(data, False)
    if status:
        return C2BIP3(decompresseddata)
    else:
        return HeuristicZlibDecompress(data)
    
def GetScriptPath():
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    else:
        return os.path.dirname(sys.argv[0])

def LoadPlugins(plugins, plugindir, verbose):
    if plugins == '':
        return

    if plugindir == '':
        scriptPath = GetScriptPath()
    else:
        scriptPath = plugindir

    for plugin in sum(map(ProcessAt, plugins.split(',')), []):
        try:
            if not plugin.lower().endswith('.py'):
                plugin += '.py'
            if os.path.dirname(plugin) == '':
                if not os.path.exists(plugin):
                    scriptPlugin = os.path.join(scriptPath, plugin)
                    if os.path.exists(scriptPlugin):
                        plugin = scriptPlugin
            exec(open(plugin, 'r').read(), globals(), globals())
        except Exception as e:
            print('Error loading plugin: %s' % plugin)
            if verbose:
                raise e

def AddDecoder(cClass):
    global decoders

    decoders.append(cClass)



def LoadDecoders(decoders, decoderdir, verbose):
    if decoders == '':
        return

    if decoderdir == '':
        scriptPath = GetScriptPath()
    else:
        scriptPath = decoderdir

    for decoder in sum(map(ProcessAt, decoders.split(',')), []):
        try:
            if not decoder.lower().endswith('.py'):
                decoder += '.py'
            if os.path.dirname(decoder) == '':
                if not os.path.exists(decoder):
                    scriptDecoder = os.path.join(scriptPath, decoder)
                    if os.path.exists(scriptDecoder):
                        decoder = scriptDecoder
            exec(open(decoder, 'r').read(), globals(), globals())
        except Exception as e:
            print('Error loading decoder: %s' % decoder)
            if verbose:
                raise e
            
def DecodeFunction(decoders, options, stream):
    if decoders == []:
        return stream
    return decoders[0](stream, options.decoderoptions).Decode()

def MacrosContainsOnlyAttributesOrOptions(stream):
    lines = SearchAndDecompress(stream).split('\n')
    for line in [line.strip() for line in lines]:
        if line != '' and not line.startswith('Attribute ') and not line == 'Option Explicit':
            return False
    return True


def Replace(string, dReplacements):
    if string in dReplacements:
        return dReplacements[string]
    else:
        return string

def ParseInteger(argument):
    sign = 1
    if argument.startswith('+'):
        argument = argument[1:]
    elif argument.startswith('-'):
        argument = argument[1:]
        sign = -1
    if argument.startswith('0x'):
        return sign * int(argument[2:], 16)
    else:
        return sign * int(argument)

def ParseCutTerm(argument):
    if argument == '':
        return CUTTERM_NOTHING, None, ''
    oMatch = re.match(r'\-?0x([0-9a-f]+)', argument, re.I)
    if oMatch == None:
        oMatch = re.match(r'\-?(\d+)', argument)
    else:
        value = int(oMatch.group(1), 16)
        if argument.startswith('-'):
            value = -value
        return CUTTERM_POSITION, value, argument[len(oMatch.group(0)):]
    if oMatch == None:
        oMatch = re.match(r'\[([0-9a-f]+)\](\d+)?([+-](?:0x[0-9a-f]+|\d+))?', argument, re.I)
    else:
        value = int(oMatch.group(1))
        if argument.startswith('-'):
            value = -value
        return CUTTERM_POSITION, value, argument[len(oMatch.group(0)):]
    if oMatch == None:
        oMatch = re.match(r"\[u?\'(.+?)\'\](\d+)?([+-](?:0x[0-9a-f]+|\d+))?", argument)
    else:
        if len(oMatch.group(1)) % 2 == 1:
            raise Exception('Uneven length hexadecimal string')
        else:
            return CUTTERM_FIND, (binascii.a2b_hex(oMatch.group(1)), int(Replace(oMatch.group(2), {None: '1'})), ParseInteger(Replace(oMatch.group(3), {None: '0'}))), argument[len(oMatch.group(0)):]
    if oMatch == None:
        return None, None, argument
    else:
        if argument.startswith("[u'"):
            # convert ascii to unicode 16 byte sequence
            searchtext = oMatch.group(1).decode('unicode_escape').encode('utf16')[2:]
        else:
            searchtext = oMatch.group(1)
        return CUTTERM_FIND, (searchtext, int(Replace(oMatch.group(2), {None: '1'})), ParseInteger(Replace(oMatch.group(3), {None: '0'}))), argument[len(oMatch.group(0)):]

def ParseCutArgument(argument):
    type, value, remainder = ParseCutTerm(argument.strip())
    if type == CUTTERM_NOTHING:
        return CUTTERM_NOTHING, None, CUTTERM_NOTHING, None
    elif type == None:
        if remainder.startswith(':'):
            typeLeft = CUTTERM_NOTHING
            valueLeft = None
            remainder = remainder[1:]
        else:
            return None, None, None, None
    else:
        typeLeft = type
        valueLeft = value
        if typeLeft == CUTTERM_POSITION and valueLeft < 0:
            return None, None, None, None
        if typeLeft == CUTTERM_FIND and valueLeft[1] == 0:
            return None, None, None, None
        if remainder.startswith(':'):
            remainder = remainder[1:]
        else:
            return None, None, None, None
    type, value, remainder = ParseCutTerm(remainder)
    if type == CUTTERM_POSITION and remainder == 'l':
        return typeLeft, valueLeft, CUTTERM_LENGTH, value
    elif type == None or remainder != '':
        return None, None, None, None
    elif type == CUTTERM_FIND and value[1] == 0:
        return None, None, None, None
    else:
        return typeLeft, valueLeft, type, value

def Find(data, value, nth, startposition=-1):
    position = startposition
    while nth > 0:
        position = data.find(value, position + 1)
        if position == -1:
            return -1
        nth -= 1
    return position

def CutData(stream, cutArgument):
    if cutArgument == '':
        return [stream, None, None]

    typeLeft, valueLeft, typeRight, valueRight = ParseCutArgument(cutArgument)

    if typeLeft == None:
        return [stream, None, None]

    if typeLeft == CUTTERM_NOTHING:
        positionBegin = 0
    elif typeLeft == CUTTERM_POSITION:
        positionBegin = valueLeft
    elif typeLeft == CUTTERM_FIND:
        positionBegin = Find(stream, valueLeft[0], valueLeft[1])
        if positionBegin == -1:
            return ['', None, None]
        positionBegin += valueLeft[2]
    else:
        raise Exception('Unknown value typeLeft')

    if typeRight == CUTTERM_NOTHING:
        positionEnd = len(stream)
    elif typeRight == CUTTERM_POSITION and valueRight < 0:
        positionEnd = len(stream) + valueRight
    elif typeRight == CUTTERM_POSITION:
        positionEnd = valueRight + 1
    elif typeRight == CUTTERM_LENGTH:
        positionEnd = positionBegin + valueRight
    elif typeRight == CUTTERM_FIND:
        positionEnd = Find(stream, valueRight[0], valueRight[1], positionBegin)
        if positionEnd == -1:
            return ['', None, None]
        else:
            positionEnd += len(valueRight[0])
        positionEnd += valueRight[2]
    else:
        raise Exception('Unknown value typeRight')

    return [stream[positionBegin:positionEnd], positionBegin, positionEnd]

def RemoveLeadingEmptyLines(data):
    if data[0] == '':
        return RemoveLeadingEmptyLines(data[1:])
    else:
        return data

def RemoveTrailingEmptyLines(data):
    if data[-1] == '':
        return RemoveTrailingEmptyLines(data[:-1])
    else:
        return data

def HeadTail(data, apply):
    count = 10
    if apply:
        lines = RemoveTrailingEmptyLines(RemoveLeadingEmptyLines(data.split('\n')))
        if len(lines) <= count * 2:
            return data
        else:
            return '\n'.join(lines[0:count] + ['...'] + lines[-count:])
    else:
        return data

def ExtraInfoMD5(data):
    return hashlib.md5(data).hexdigest()

def ExtraInfoSHA1(data):
    return hashlib.sha1(data).hexdigest()

def ExtraInfoSHA256(data):
    return hashlib.sha256(data).hexdigest()

def CalculateByteStatistics(dPrevalence):
    sumValues = sum(dPrevalence.values())
    countNullByte = dPrevalence[0]
    countControlBytes = 0
    countWhitespaceBytes = 0
    for iter in range(1, 0x21):
        if chr(iter) in string.whitespace:
            countWhitespaceBytes += dPrevalence[iter]
        else:
            countControlBytes += dPrevalence[iter]
    countControlBytes += dPrevalence[0x7F]
    countPrintableBytes = 0
    for iter in range(0x21, 0x7F):
        countPrintableBytes += dPrevalence[iter]
    countHighBytes = 0
    for iter in range(0x80, 0x100):
        countHighBytes += dPrevalence[iter]
    entropy = 0.0
    for iter in range(0x100):
        if dPrevalence[iter] > 0:
            prevalence = float(dPrevalence[iter]) / float(sumValues)
            entropy += - prevalence * math.log(prevalence, 2)
    return sumValues, entropy, countNullByte, countControlBytes, countWhitespaceBytes, countPrintableBytes, countHighBytes

def ExtraInfoENTROPY(data):
    dPrevalence = {iter: 0 for iter in range(0x100)}
    for char in data:
        dPrevalence[P23Ord(char)] += 1
    sumValues, entropy, countNullByte, countControlBytes, countWhitespaceBytes, countPrintableBytes, countHighBytes = CalculateByteStatistics(dPrevalence)
    return '%f' % entropy

def ExtraInfoHEADHEX(data):
    if data == None:
        return ''
    return binascii.hexlify(data[:16]).decode()

def ExtraInfoHEADASCII(data):
    if data == None:
        return ''
    return ''.join([IFF(P23Ord(b) >= 32 and P23Ord(b) < 127, P23Chr(b), '.') for b in data[:16]])

def ExtraInfoTAILHEX(data):
    if data == None:
        return ''
    return binascii.hexlify(data[-16:]).decode()

def ExtraInfoTAILASCII(data):
    if data == None:
        return ''
    return ''.join([IFF(P23Ord(b) >= 32 and P23Ord(b) < 127, P23Chr(b), '.') for b in data[-16:]])

def ExtraInfoHISTOGRAM(data):
    dPrevalence = {iter: 0 for iter in range(0x100)}
    for char in data:
        dPrevalence[P23Ord(char)] += 1
    result = []
    count = 0
    minimum = None
    maximum = None
    for iter in range(0x100):
        if dPrevalence[iter] > 0:
            result.append('0x%02x:%d' % (iter, dPrevalence[iter]))
            count += 1
            if minimum == None:
                minimum = iter
            else:
                minimum = min(minimum, iter)
            if maximum == None:
                maximum = iter
            else:
                maximum = max(maximum, iter)
    result.insert(0, '%d' % count)
    result.insert(1, IFF(minimum == None, '', '0x%02x' % minimum))
    result.insert(2, IFF(maximum == None, '', '0x%02x' % maximum))
    return ','.join(result)

def ExtraInfoBYTESTATS(data):
    dPrevalence = {iter: 0 for iter in range(0x100)}
    for char in data:
        dPrevalence[P23Ord(char)] += 1
    sumValues, entropy, countNullByte, countControlBytes, countWhitespaceBytes, countPrintableBytes, countHighBytes = CalculateByteStatistics(dPrevalence)
    return '%d,%d,%d,%d,%d' % (countNullByte, countControlBytes, countWhitespaceBytes, countPrintableBytes, countHighBytes)

def FormatFiletime(filetime):
    if filetime == 0:
        return '0'

    FILETIME19700101 = 116444736000000000
    oDatetime = datetime.datetime.fromtimestamp((filetime - FILETIME19700101) / 10000000, datetime.timezone.utc)
    return oDatetime.isoformat()

def GenerateExtraInfo(extra, index, indicator, moduleinfo, name, entry_metadata, stream):
    if extra == '':
        return ''
    if extra.startswith('!'):
        extra = extra[1:]
        prefix = ''
    else:
        prefix = ' '
#    if indicator == ' ':
#        indicator = ''
    moduleinfo = moduleinfo.strip()
    if moduleinfo == '':
        moduleinfo = 'N/A'
    if KNOWN_CLSIDS == {}:
        clsidDesc = '<oletools missing>'
    else:
        clsidDesc = KNOWN_CLSIDS.get(entry_metadata[0].upper(), '')
    dExtras = {'%INDEX%': lambda x: index,
               '%INDICATOR%': lambda x: indicator,
               '%LENGTH%': lambda x: '%d' % len(stream),
               '%NAME%': lambda x: name,
               '%MD5%': ExtraInfoMD5,
               '%SHA1%': ExtraInfoSHA1,
               '%SHA256%': ExtraInfoSHA256,
               '%ENTROPY%': ExtraInfoENTROPY,
               '%HEADHEX%': ExtraInfoHEADHEX,
               '%HEADASCII%': ExtraInfoHEADASCII,
               '%TAILHEX%': ExtraInfoTAILHEX,
               '%TAILASCII%': ExtraInfoTAILASCII,
               '%HISTOGRAM%': ExtraInfoHISTOGRAM,
               '%BYTESTATS%': ExtraInfoBYTESTATS,
               '%CLSID%': lambda x: entry_metadata[0],
               '%CLSIDDESC%': lambda x: clsidDesc,
               '%MODULEINFO%': lambda x: moduleinfo,
               '%CTIME%': lambda x: FormatFiletime(entry_metadata[1]),
               '%MTIME%': lambda x: FormatFiletime(entry_metadata[2]),
               '%CTIMEHEX%': lambda x: '%016x' % entry_metadata[1],
               '%MTIMEHEX%': lambda x: '%016x' % entry_metadata[2],
              }
    for variable in dExtras:
        if variable in extra:
            extra = extra.replace(variable, dExtras[variable](stream))
    return prefix + extra.replace(r'\t', '\t').replace(r'\n', '\n')

def OLE10HeaderPresent(data):
    length = len(data)
    if length < 6:
        return False
    size, data = ReadDWORD(data)
    if size == None:
        return False
    if size + 4 != length:
        return False
    version, data = ReadWORD(data)
    return version ==2

def GetUnusedData(ole, fname):
    sid = ole._find(fname)
    entry = ole.direntries[sid]
    if entry.size < ole.minisectorcutoff:
        increase = ole.minisectorsize
    else:
        increase = ole.sectorsize
    currentsize = entry.size
    lendata = currentsize
    while True:
        currentsize += increase
        data = ole._open(entry.isectStart, currentsize).read()
        if len(data) == lendata:
            return data[entry.size:]
        else:
            lendata = len(data)

def OLEGetStreams(ole, storages, unuseddata):
    olestreams = []
    if storages:
        olestreams.append([0, [ole.root.name], ole.root.entry_type, [ole.root.clsid, ole.root.createTime, ole.root.modifyTime], '', 0])
    for fname in ole.listdir(storages=storages):
        unusedData = b''
        if ole.get_type(fname) == 1:
            data = b''
        else:
            data = ole.openstream(fname).read()
            if unuseddata:
                unusedData = GetUnusedData(ole, fname)
        direntry = ole.direntries[ole._find(fname)]
        olestreams.append([0, fname, ole.get_type(fname), [ole.getclsid(fname), direntry.createTime, direntry.modifyTime], data + unusedData, len(unusedData)])
    for sid in range(len(ole.direntries)):
        entry = ole.direntries[sid]
        if entry is None:
            entry = ole._load_direntry(sid)
            if entry.entry_type == 2:
                olestreams.append([1, entry.name, entry.entry_type, ['', 0, 0], ole._open(entry.isectStart, entry.size).read(), 0])
    return olestreams

def SelectPart(stream, part, moduleinfodata):
    if part == '':
        return stream
    if not part in ['c', 's']:
        return ''
    if moduleinfodata == None:
        return ''
    if part == 'c':
        return stream[:moduleinfodata[6]]
    else:
        return stream[moduleinfodata[6]:]

def ParseVBADIR(ole):
    vbadirinfo = []
    for fname in ole.listdir():
        if len(fname) >= 2 and fname[-2] == 'VBA' and fname[-1] == 'dir':
            vbadirinfo = [fname]
            status, vbadirdata = Decompress(ole.openstream(fname).read(), False)
            if status:
                for position in FindAll(vbadirdata, '\x0F\x00\x02\x00\x00\x00'):
                    result = struct.unpack('<HIHHIHH', C2BIP3(vbadirdata[position:][0:18]))
                    if result[3] == 0x13 and result[4] == 0x02 and result[6] == 0x19:
                        vbadirinfo.append(result[2])
                        moduledata = vbadirdata[position + 16:]
                        moduleinfo = {}
                        while len(moduledata) > 2 and moduledata[0:2] == '\x19\x00':
                            result = struct.unpack('<HI', C2BIP3(moduledata[0:6]))
                            moduledata = moduledata[6:]
                            namerecord = moduledata[0:result[1]]
                            moduledata = moduledata[result[1]:]
                            result = struct.unpack('<HI', C2BIP3(moduledata[0:6]))
                            if result[0] != 0x47:
                                break
                            moduledata = moduledata[6:]
                            nameunicoderecord = moduledata[0:result[1]]
                            moduledata = moduledata[result[1]:]
                            result = struct.unpack('<HI', C2BIP3(moduledata[0:6]))
                            if result[0] != 0x1A:
                                break
                            moduledata = moduledata[6:]
                            streamnamerecord = moduledata[0:result[1]]
                            moduledata = moduledata[result[1]:]
                            result = struct.unpack('<HI', C2BIP3(moduledata[0:6]))
                            if result[0] != 0x32:
                                break
                            moduledata = moduledata[6:]
                            streamnameunicoderecord = moduledata[0:result[1]]
                            moduledata = moduledata[result[1]:]
                            result = struct.unpack('<HI', C2BIP3(moduledata[0:6]))
                            if result[0] != 0x1C:
                                break
                            moduledata = moduledata[6:]
                            docstringrecordrecord = moduledata[0:result[1]]
                            moduledata = moduledata[result[1]:]
                            result = struct.unpack('<HI', C2BIP3(moduledata[0:6]))
                            if result[0] != 0x48:
                                break
                            moduledata = moduledata[6:]
                            docstringunicoderecordrecord = moduledata[0:result[1]]
                            moduledata = moduledata[result[1]:]
                            result = struct.unpack('<HII', C2BIP3(moduledata[0:10]))
                            if result[0] != 0x31 or result[1] != 0x04:
                                break
                            moduledata = moduledata[10:]
                            moduleoffset = result[2]
                            moduledata = moduledata[10 + 8 + 6:]
                            if moduledata[0:2] != '\x2B\x00':
                                moduledata = moduledata[6:]
                            if moduledata[0:2] != '\x2B\x00':
                                moduledata = moduledata[6:]
                            moduledata = moduledata[2 + 4:]
                            moduleinfo[streamnameunicoderecord] = [namerecord, nameunicoderecord, streamnamerecord, streamnameunicoderecord, docstringrecordrecord, docstringunicoderecordrecord, moduleoffset]
                        if moduleinfo != {}:
                            vbadirinfo.append(moduleinfo)
    return vbadirinfo

def PrintUserdefinedProperties(ole, streamname):
    if not 'get_userdefined_properties' in dir(ole):
        return
    userdefinedproperties = ole.get_userdefined_properties(streamname)
    if len(userdefinedproperties) > 0:
        print('User defined properties:')
        for userdefinedproperty in userdefinedproperties:
            print(' %s: %s' % (userdefinedproperty['property_name'], userdefinedproperty['value']))

class cMyJSONOutput():

    def __init__(self):
        self.items = []
        self.counter = 1

    def AddIdItem(self, id, name, data):
        self.items.append({'id': id, 'name': name, 'content': binascii.b2a_base64(data).strip(b'\n').decode()})

    def AddItem(self, name, data):
        self.AddIdItem(self.counter, name, data)
        self.counter += 1

    def GetJSON(self):
        return json.dumps({'version': 2, 'id': 'didierstevens.com', 'type': 'content', 'fields': ['id', 'name', 'content'], 'items': self.items})

def OLESub(ole, data, prefix, rules, options):
    global plugins
    global pluginsOle
    global decoders

    returnCode = 1
    selectionCounter = 0

    if options.metadata:
        metadata = ole.get_metadata()
        print('Properties SummaryInformation:')
        for attribute in metadata.SUMMARY_ATTRIBS:
            value = getattr(metadata, attribute)
            if value != None:
                if attribute == 'codepage':
                    print(' %s: %s %s' % (attribute, value, LookupCodepage(value)))
                else:
                    print(' %s: %s' % (attribute, value))
        PrintUserdefinedProperties(ole, ['\x05SummaryInformation'])

        print('Properties DocumentSummaryInformation:')
        for attribute in metadata.DOCSUM_ATTRIBS:
            value = getattr(metadata, attribute)
            if value != None:
                if attribute == 'codepage_doc':
                    print(' %s: %s %s' % (attribute, value, LookupCodepage(value)))
                else:
                    print(' %s: %s' % (attribute, value))
        PrintUserdefinedProperties(ole, ['\x05DocumentSummaryInformation'])

        return (returnCode, 0)

    if options.jsonoutput:
        oMyJSONOutput = cMyJSONOutput()
        if options.vbadecompress:
            counter = 1
            for orphan, fname, entry_type, entry_metadata, stream, sizeUnusedData in OLEGetStreams(ole, options.storages, options.unuseddata):
                vbacode = SearchAndDecompress(stream, '')
                if vbacode != '':
                    oMyJSONOutput.AddIdItem(counter, PrintableName(fname), vbacode.encode())
                counter += 1
        else:
            for orphan, fname, entry_type, entry_metadata, stream, sizeUnusedData in OLEGetStreams(ole, options.storages, options.unuseddata):
                oMyJSONOutput.AddItem(PrintableName(fname), stream)
        print(oMyJSONOutput.GetJSON())
        return (returnCode, 0)

    vbadirinfo = ParseVBADIR(ole)
    if len(vbadirinfo) == 3:
        dModuleinfo = vbadirinfo[2]
    else:
        dModuleinfo = {}

    if options.select == '':
        counter = 1
        vbaConcatenate = ''
        objectsPluginOle = [cPluginOle(ole, data, options.pluginoptions) for cPluginOle in pluginsOle]
        for oPluginOle in objectsPluginOle:
            oPluginOle.PreProcess()

        for orphan, fname, entry_type, entry_metadata, stream, sizeUnusedData in OLEGetStreams(ole, options.storages, options.unuseddata):
            indicator = ' '
            macroPresent = False
            if options.info:
                moduleinfo = ' ' * 12
            else:
                moduleinfo = ''
            if options.unuseddata:
                lengthString = '            '
            else:
                lengthString = '       '
            if entry_type == 5:
                indicator = 'R'
            elif entry_type == 1:
                indicator = '.'
            elif entry_type == 2:
                if options.unuseddata:
                    lengthString = '%d(%d)' % (len(stream), sizeUnusedData)
                    lengthString = '%12s' % lengthString
                else:
                    lengthString = '%7d' % len(stream)
                moduleinfodata = dModuleinfo.get(''.join([c + '\x00' for c in fname[-1]]), None)
                if options.info and moduleinfodata != None:
                    moduleinfo = '%d+%d' % (moduleinfodata[6], len(stream) - moduleinfodata[6])
                    moduleinfo = '%12s' % moduleinfo
                macroPresent = FindCompression(stream) != -1
                if macroPresent:
                    returnCode = 2
                    if not SearchAndDecompressSub(stream)[0]:
                        indicator = 'E'
                    else:
                        indicator = 'M'
                        if MacrosContainsOnlyAttributesOrOptions(stream):
                            indicator = 'm'
                elif not macroPresent and moduleinfodata != None:
                    indicator = '!'
                elif OLE10HeaderPresent(stream):
                    indicator = 'O'
            index = '%s%d' % (prefix, counter)
            if not options.quiet:
                line = '%3s: %s %s%s %s' % (index, indicator, lengthString, moduleinfo, PrintableName(fname, orphan))
                if indicator.lower() == 'm' and options.vbadecompress:
                    streamForExtra = SearchAndDecompress(stream).encode()
                else:
                    streamForExtra = stream
                if options.calc:
                    line += ' %s' % hashlib.md5(streamForExtra).hexdigest()
                if options.extra.startswith('!'):
                    line = ''
                line += GenerateExtraInfo(options.extra, index, indicator, moduleinfo, PrintableName(fname, orphan), entry_metadata, streamForExtra)
                print(line)
            for cPlugin in plugins:
                try:
                    if cPlugin.macroOnly and macroPresent:
                        oPlugin = cPlugin(fname, SearchAndDecompress(stream), options.pluginoptions)
                    elif not cPlugin.macroOnly:
                        oPlugin = cPlugin(fname, stream, options.pluginoptions)
                    else:
                        oPlugin = None
                except Exception as e:
                    print('Error instantiating plugin: %s' % cPlugin.name)
                    if options.verbose:
                        raise e
                    return (returnCode, 0)
                if oPlugin != None:
                    result = oPlugin.Analyze()
                    if oPlugin.ran:
                        if options.quiet:
                            if oPlugin.indexQuiet:
                                if result != []:
                                    print('%3s: %s' % (index, MyRepr(result[0])))
                            elif type(result) == str or type(result) == bytes:
                                IfWIN32SetBinary(sys.stdout)
                                StdoutWriteChunked(result)
                            else:
                                for line in result:
                                    print(MyRepr(line))
                        else:
                            print('               Plugin: %s ' % oPlugin.name)
                            if type(result) == str:
                                print('                 use option -q to dump the following data')
                                print('                 ' + MyRepr(result))
                            else:
                                for line in result:
                                    print('                 ' + MyRepr(line))

            for oPluginOle in objectsPluginOle:
                oPluginOle.Process(fname, stream)

            counter += 1
            if options.yara != None:
                oDecoders = [cIdentity(stream, None)]
                for cDecoder in decoders:
                    try:
                        oDecoder = cDecoder(stream, options.decoderoptions)
                        oDecoders.append(oDecoder)
                    except Exception as e:
                        print('Error instantiating decoder: %s' % cDecoder.name)
                        if options.verbose:
                            raise e
                        return (returnCode, 0)
                for oDecoder in oDecoders:
                    while oDecoder.Available():
                        for result in rules.match(data=oDecoder.Decode(), externals={'streamname': PrintableName(fname), 'VBA': False}):
                            print('               YARA rule%s: %s' % (IFF(oDecoder.Name() == '', '', ' (stream decoder: %s)' % oDecoder.Name()), result.rule))
                            if options.yarastrings:
                                for stringdata in result.strings:
                                    print('               %06x %s:' % (stringdata[0], stringdata[1]))
                                    print('                %s' % binascii.hexlify(C2BIP3(stringdata[2])))
                                    print('                %s' % repr(stringdata[2]))
            if indicator.lower() == 'm':
                vbaConcatenate += SearchAndDecompress(stream) + '\n'

        if options.yara != None and vbaConcatenate != '':
            print('All VBA source code:')
            for result in rules.match(data=vbaConcatenate, externals={'streamname': '', 'VBA': True}):
                print('               YARA rule: %s' % result.rule)
                if options.yarastrings:
                    for stringdata in result.strings:
                        print('               %06x %s:' % (stringdata[0], stringdata[1]))
                        print('                %s' % binascii.hexlify(C2BIP3(stringdata[2])))
                        print('                %s' % repr(stringdata[2]))

        for oPluginOle in objectsPluginOle:
            oPluginOle.PostProcess()

    else:
        if len(decoders) > 1:
            print('Error: provide only one decoder when using option select')
            return (returnCode, 0)
        if options.decompress:
            DecompressFunction = HeuristicDecompress
        else:
            DecompressFunction = lambda x:x
        if options.dump:
            DumpFunction = lambda x:x
            IfWIN32SetBinary(sys.stdout)
        elif options.hexdump:
            DumpFunction = HexDump
        elif options.vbadecompress:
            if options.select == 'a':
                DumpFunction = lambda x: SearchAndDecompress(x, '')
            else:
                DumpFunction = SearchAndDecompress
        elif options.vbadecompressskipattributes:
            if options.select == 'a':
                DumpFunction = lambda x: SearchAndDecompress(x, '', True)
            else:
                DumpFunction = lambda x: SearchAndDecompress(x, skipAttributes=True)
        elif options.vbadecompresscorrupt:
            DumpFunction = lambda x: SearchAndDecompress(x, None)
        elif options.extract:
            DumpFunction = Extract
            IfWIN32SetBinary(sys.stdout)
        elif options.info:
            DumpFunction = Info
        elif options.translate != '':
            DumpFunction = Translate(options.translate)
        elif options.strings:
            DumpFunction = DumpFunctionStrings
        elif options.asciidumprle:
            DumpFunction = lambda x: HexAsciiDump(x, True)
        else:
            DumpFunction = HexAsciiDump

        counter = 1
        if options.select.endswith('c') or options.select.endswith('s'):
            selection = options.select[:-1]
            part = options.select[-1]
        else:
            selection = options.select
            part = ''
        for orphan, fname, entry_type, entry_metadata, stream, sizeUnusedData in OLEGetStreams(ole, options.storages, options.unuseddata):
            if selection == 'a' or ('%s%d' % (prefix, counter)) == selection.upper() or prefix == 'A' and str(counter) == selection or PrintableName(fname).lower() == selection.lower():
                StdoutWriteChunked(HeadTail(DumpFunction(DecompressFunction(DecodeFunction(decoders, options, CutData(SelectPart(stream, part, dModuleinfo.get(''.join([c + '\x00' for c in fname[-1]]), None)), options.cut)[0]))), options.headtail))
                selectionCounter += 1
                if selection != 'a':
                    break
            counter += 1

    return (returnCode, selectionCounter)

def YARACompile(ruledata):
    if ruledata.startswith('#'):
        if ruledata.startswith('#h#'):
            rule = binascii.a2b_hex(ruledata[3:])
        elif ruledata.startswith('#b#'):
            rule = binascii.a2b_base64(ruledata[3:])
        elif ruledata.startswith('#s#'):
            rule = 'rule string {strings: $a = "%s" ascii wide nocase condition: $a}' % ruledata[3:]
        elif ruledata.startswith('#q#'):
            rule = ruledata[3:].replace("'", '"')
        elif ruledata.startswith('#x#'):
            rule = 'rule hexadecimal {strings: $a = { %s } condition: $a}' % ruledata[3:]
        elif ruledata.startswith('#r#'):
            rule = 'rule regex {strings: $a = /%s/ ascii wide nocase condition: $a}' % ruledata[3:]
        else:
            rule = ruledata[1:]
        return yara.compile(source=rule, externals={'streamname': '', 'VBA': False}), rule
    else:
        dFilepaths = {}
        if os.path.isdir(ruledata):
            for root, dirs, files in os.walk(ruledata):
                for file in files:
                    filename = os.path.join(root, file)
                    dFilepaths[filename] = filename
        else:
            for filename in ProcessAt(ruledata):
                dFilepaths[filename] = filename
        return yara.compile(filepaths=dFilepaths, externals={'streamname': '', 'VBA': False}), ','.join(dFilepaths.values())

def PrintWarningSelection(select, selectionCounter):
    if select != '' and selectionCounter == 0:
        print('Warning: no stream was selected with expression %s' % select)

def CreateZipFileObject(arg1, arg2):
    if 'AESZipFile' in dir(zipfile):
        return zipfile.AESZipFile(arg1, arg2)
    else:
        return zipfile.ZipFile(arg1, arg2)


dSpecialHashes = {'crc32': cHashCRC32, 'checksum8': cHashChecksum8}

def GetHashObjects(algorithms):
    global dSpecialHashes
    
    dHashes = {}

    if algorithms == '':
        algorithms = os.getenv('DSS_DEFAULT_HASH_ALGORITHMS', 'md5')
    if ',' in algorithms:
        hashes = algorithms.split(',')
    else:
        hashes = algorithms.split(';')
    for name in hashes:
        if not name in dSpecialHashes.keys() and not name in hashlib.algorithms_available:
            print('Error: unknown hash algorithm: %s' % name)
            print('Available hash algorithms: ' + ' '.join([name for name in list(hashlib.algorithms_available)] + list(dSpecialHashes.keys())))
            return [], {}
        elif name in dSpecialHashes.keys():
            dHashes[name] = dSpecialHashes[name]()
        else:
            dHashes[name] = hashlib.new(name)

    return hashes, dHashes

def CalculateChosenHash(data):
    hashes, dHashes = GetHashObjects('')
    dHashes[hashes[0]].update(data)
    return dHashes[hashes[0]].hexdigest(), hashes[0]


def OptionsEnvironmentVariables(options):
    if options.extra == '':
        options.extra = os.getenv('OLEDUMP_EXTRA', options.extra)