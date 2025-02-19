def FindAll(data: bytes, sub: bytes):
    result = []
    start = 0
    while True:
        position = data.find(sub, start)
        if position == -1:
            return result
        result.append(position)
        start = position + 1