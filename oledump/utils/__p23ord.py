def p23ord(value: str | bytes | bytearray | int) -> int:
    if isinstance(value, int):
        return value
    
    else:
        return ord(value)