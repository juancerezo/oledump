def P23Ord(value: str | bytes | bytearray | int) -> int:
    if isinstance(value, int):
        return value
    
    else:
        return ord(value)