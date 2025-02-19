from .p23ord import P23Ord
import math

def OffsetBits(data: bytes) -> int:
    numberOfBits = int(math.ceil(math.log(len(data), 2)))
    if numberOfBits < 4:
        numberOfBits = 4
    elif numberOfBits > 12:
        numberOfBits = 12
    return numberOfBits

def ParseTokenSequence(data: bytes) -> tuple[list[bytes], bytes]:

    flags = P23Ord(data[0])
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

def DecompressChunk(compressedChunk) -> tuple[bytes, bytes] | tuple[None, None]:
    if len(compressedChunk) < 2:
        return None, None
    
    header = P23Ord(compressedChunk[0]) + P23Ord(compressedChunk[1]) * 0x100
    size = (header & 0x0FFF) + 3
    flagCompressed = header & 0x8000
    data = compressedChunk[2:2 + size - 2]

    if flagCompressed == 0:
        return data.decode(errors='ignore'), compressedChunk[size:]

    decompressedChunk: bytes = b''
    while len(data) != 0:

        tokens, data = ParseTokenSequence(data)
        for token in tokens:
            if len(token) == 1:

                decompressedChunk += token

            else:
                if decompressedChunk == b'':
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

def Decompress(compressedData: bytes, replace=True):

    if P23Ord(compressedData[0]) != 1:
        return (False, None)
    
    remainder: bytes = compressedData[1:]
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

def FindCompression(data: bytes):
    return data.find(b'\x00Attribut\x00e ')

def SearchAndDecompressSub(data: bytes):
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