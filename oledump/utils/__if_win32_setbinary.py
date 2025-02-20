import sys
from typing import TextIO, Any

def if_win32_setbinary(io: TextIO | Any):
    if sys.platform == 'win32':
        import msvcrt
        msvcrt.setmode(io.fileno(), os.O_BINARY)