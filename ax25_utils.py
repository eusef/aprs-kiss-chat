
def decode_ax25_address_field(data: bytes) -> (list, int):
    """
    Decodes AX.25 address fields from the given data.
    
    Returns a tuple of (list of call sign strings, index after address field).
    Each address is 7 bytes. The final address has its LSB set.
    """
    addresses = []
    idx = 0
    while idx + 7 <= len(data):
        addr = data[idx:idx+7]
        idx += 7
        callsign = ''.join(chr(b >> 1) for b in addr[:6]).strip()
        ssid = (addr[6] >> 1) & 0x0F
        if ssid:
            callsign = f"{callsign}-{ssid}"
        addresses.append(callsign)
        if addr[6] & 0x01:  # last address flag
            break
    return addresses, idx

def decode_ax25_packet(packet: bytes) -> str:
    """
    Decodes an AX.25 packet into a human-readable string.
    """
    if len(packet) < 16:
        return packet.decode('latin1', errors='replace')
    
    addresses, idx = decode_ax25_address_field(packet)
    if idx + 2 > len(packet):
        return packet.decode('latin1', errors='replace')
    
    control = packet[idx]
    pid = packet[idx+1]
    info = packet[idx+2:]
    info_str = info.decode('latin1', errors='replace')
    
    destination = addresses[0] if len(addresses) > 0 else ""
    source = addresses[1] if len(addresses) > 1 else ""
    digipeaters = addresses[2:] if len(addresses) > 2 else []
    
    header = f"{source} > {destination}"
    if digipeaters:
        header += f" via {', '.join(digipeaters)}"
    header += f" (Ctrl: 0x{control:02X}, PID: 0x{pid:02X})"
    
    return f"{header} : {info_str}"

def ax25_encode_address(callsign: str, last: bool) -> bytes:
    """
    Encodes a call sign (with optional "-SSID") into a 7-byte AX.25 address field.
    """
    parts = callsign.strip().upper().split('-')
    call = parts[0].ljust(6)
    ssid = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
    encoded = bytearray()
    for char in call:
        encoded.append(ord(char) << 1)
    byte7 = ((ssid & 0x0F) << 1) | 0x60
    if last:
        byte7 |= 0x01
    else:
        byte7 &= 0xFE
    encoded.append(byte7)
    return bytes(encoded)

def build_ax25_message_packet(source: str, destination: str, digipeaters: list, message_text: str, msg_id: str) -> bytes:
    """
    Builds a proper AX.25 message packet.
    
    The header is constructed as:
      - Destination (always first, not marked last if additional addresses follow)
      - Source (marked last only if no digipeaters are provided)
      - Zero or more digipeater addresses (the final digipeater is marked as last)
    
    Then appends the control (0x03), PID (0xF0), and information field (starting with a colon).
    """
    addresses = bytearray()
    # Destination is always first; not the last field if more addresses follow.
    addresses += ax25_encode_address(destination, last=False)
    
    # Source is next; mark as not last if digipeaters exist.
    if digipeaters:
        addresses += ax25_encode_address(source, last=False)
    else:
        addresses += ax25_encode_address(source, last=True)
    
    # Process digipeaters if provided.
    if digipeaters:
        # For each digipeater except the last, last=False.
        for digi in digipeaters[:-1]:
            addresses += ax25_encode_address(digi, last=False)
        # The final digipeater gets last=True.
        addresses += ax25_encode_address(digipeaters[-1], last=True)
    
    control = bytes([0x03])
    pid = bytes([0xF0])
    
    # Ensure destination is 9 characters long
    destination = destination.ljust(9)
    
    if msg_id:
        info = f":{destination}:{message_text}{{{msg_id}}}".encode('ascii')
    else:
        info = f":{destination}:{message_text}".encode('ascii')
    return bytes(addresses) + control + pid + info