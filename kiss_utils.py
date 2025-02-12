# KISS protocol constants
FEND  = 0xC0  # Frame delimiter
FESC  = 0xDB  # Escape character
TFEND = 0xDC  # Escaped FEND value
TFESC = 0xDD  # Escaped FESC value

def kiss_encode(data: bytes) -> bytes:
    """
    Encodes raw data into a KISS frame using command byte 0x00.
    """
    encoded = bytearray()
    encoded.append(0x00)
    for b in data:
        if b == FEND:
            encoded.extend([FESC, TFEND])
        elif b == FESC:
            encoded.extend([FESC, TFESC])
        else:
            encoded.append(b)
    return bytes([FEND]) + bytes(encoded) + bytes([FEND])

def kiss_decode(frame: bytes) -> bytes:
    """
    Decodes a KISS frame (assumes frame starts and ends with FEND).
    """
    if frame.startswith(bytes([FEND])):
        frame = frame[1:]
    if frame.endswith(bytes([FEND])):
        frame = frame[:-1]
    payload = frame[1:]  # Skip command byte
    decoded = bytearray()
    i = 0
    while i < len(payload):
        b = payload[i]
        if b == FESC:
            i += 1
            if i < len(payload):
                next_b = payload[i]
                if next_b == TFEND:
                    decoded.append(FEND)
                elif next_b == TFESC:
                    decoded.append(FESC)
                else:
                    decoded.append(next_b)
        else:
            decoded.append(b)
        i += 1
    return bytes(decoded)