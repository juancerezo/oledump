import math
import re

from .__p23ord import p23ord

def OffsetBits(data: bytes) -> int:
    numberOfBits = int(math.ceil(math.log(len(data), 2)))
    if numberOfBits < 4:
        numberOfBits = 4
    elif numberOfBits > 12:
        numberOfBits = 12
    return numberOfBits

def ParseTokenSequence(data: bytes) -> tuple[list[bytes], bytes]:

    flags = p23ord(data[0])
    data = data[1:]
    result: list[bytes] = []

    for mask in [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80]:
        if len(data) > 0:
            if flags & mask:
                result.append(data[0:2])
                data = data[2:]
            else:
                result.append(data[0].to_bytes())
                data = data[1:]

    return result, data

def DecompressChunk(compressedChunk: bytes) -> tuple[bytes | None, bytes]:
    if len(compressedChunk) < 2:
        return None, b''
    
    header = p23ord(compressedChunk[0]) + p23ord(compressedChunk[1]) * 0x100
    size = (header & 0x0FFF) + 3
    flagCompressed = header & 0x8000
    data = compressedChunk[2:2 + size - 2]

    if flagCompressed == 0:
        return data, compressedChunk[size:]

    decompressedChunk: bytes = b''
    while len(data) != 0:

        tokens, data = ParseTokenSequence(data)
        for token in tokens:
            if len(token) == 1:

                decompressedChunk += token

            else:
                if decompressedChunk == b'':
                    return None, b''
                
                numberOfOffsetBits = OffsetBits(decompressedChunk)
                copyToken = p23ord(token[0]) + p23ord(token[1]) * 0x100

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

def Decompress(compressedData: bytes, replace=True) -> tuple[bool, bytes | None]:

    if p23ord(compressedData[0]) != 1:
        return (False, None)
    
    remainder: bytes = compressedData[1:]
    decompressed = b''

    while remainder and len(remainder) != 0:
        decompressedChunk, remainder = DecompressChunk(remainder)
        if decompressedChunk == None:
            return (False, decompressed)
        
        decompressed += decompressedChunk

    if replace:
        return (True, decompressed.replace(b'\r\n', b'\n'))
    else:
        return (True, decompressed)

def FindCompression(data: bytes) -> int:
    return data.find(b'\x00Attribut\x00e ')

def SearchAndDecompressSub(data: bytes) -> tuple[bool, bytes | None]:
    position = FindCompression(data)
    if position == -1:
        return (False, b'')
    else:
        compressedData = data[position - 3:]
    return Decompress(compressedData)

def SkipAttributes(data: bytes) -> bytes:
    oAttribute = re.compile(b'^Attribute VB_.+? = [^\n]+\n')
    while True:
        oMatch = oAttribute.match(data)
        if oMatch == None:
            break
        data = data[len(oMatch.group()):]

    return data

def search_and_decompress(*, data: bytes, ignore_errors: bool = False, skip_attributes: bool =False) -> tuple[bytes | None, str | None]:
    result, decompress = SearchAndDecompressSub(data)
    if result or ignore_errors is True:
        if skip_attributes and decompress is not None:
            return SkipAttributes(decompress), None
        else:
            return decompress, None
        
    else:
        return None, 'Error: unable to decompress\n'