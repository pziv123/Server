import struct

def Pack(Type: int, Info: bytes):
    return struct.pack("!BI", Type, len(Info)) + Info


def Unpack(data: bytes):
    HeaderSize = struct.calcsize("!BI")
    if len(data) < HeaderSize:
        raise ValueError("Packet too small")

    Type, Length = struct.unpack("!BI", data[:HeaderSize])

    if len(data) < HeaderSize + Length:
        raise ValueError("Incomplete packet")

    Data = data[HeaderSize:HeaderSize + Length]

    return Type, Data, Length