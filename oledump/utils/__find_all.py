def find_all(data: bytes, sub: bytes) -> list[int]:
    result: list[int] = []
    start = 0
    while True:
        position = data.find(sub, start)
        if position == -1:
            return result
        result.append(position)
        start = position + 1