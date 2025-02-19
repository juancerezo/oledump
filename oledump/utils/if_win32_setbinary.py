import sys
from typing import TextIO, Any

def IfWIN32SetBinary(io: TextIO | Any):
    if sys.platform == 'win32':
        import msvcrt
        msvcrt.setmode(io.fileno(), os.O_BINARY)