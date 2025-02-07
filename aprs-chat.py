#!/usr/bin/env python3
import socket
import threading
import time
import sys

# KISS protocol constants
FEND  = 0xC0  # Frame delimiter
FESC  = 0xDB  # Escape character
TFEND = 0xDC  # Escaped FEND value
TFESC = 0xDD  # Escaped FESC value

# Global locks and dictionary for heard stations
log_lock = threading.Lock()
heard_lock = threading.Lock()
heard_stations = {}  # Maps station call sign -> most recent packet (human-readable)

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

def log_message(message: str, logfile) -> None:
    """
    Logs a message to the console and the log file.
    """
    with log_lock:
        print(message)
        logfile.write(message + "\n")
        logfile.flush()

def receiver(sock: socket.socket, logfile, exit_event: threading.Event) -> None:
    """
    Continuously receives data, decodes KISS frames and AX.25 packets,
    logs them, and updates the heard stations dictionary.
    """
    buffer = bytearray()
    while not exit_event.is_set():
        try:
            data = sock.recv(4096)
        except socket.timeout:
            continue
        except Exception as e:
            log_message(f"Receiver error: {e}", logfile)
            exit_event.set()
            break

        if not data:
            log_message("Connection closed by remote host", logfile)
            exit_event.set()
            break

        buffer.extend(data)
        while True:
            start_index = buffer.find(bytes([FEND]))
            if start_index == -1:
                break
            end_index = buffer.find(bytes([FEND]), start_index + 1)
            if end_index == -1:
                break  # Incomplete frame; wait for more data
            frame = bytes(buffer[start_index:end_index+1])
            del buffer[:end_index+1]
            decoded_bytes = kiss_decode(frame)
            decoded_str = decode_ax25_packet(decoded_bytes)
            log_message(f"Received: {decoded_str}", logfile)
            # Update heard stations with the most recent packet from the source.
            try:
                addresses, _ = decode_ax25_address_field(decoded_bytes)
                if len(addresses) > 1:
                    source = addresses[1]
                    with heard_lock:
                        heard_stations[source] = decoded_str
            except Exception:
                pass

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
    if msg_id:
        info = f"::{destination}:{message_text}{{{msg_id}}}".encode('ascii')
    else:
        info = f"::{destination}:{message_text}".encode('ascii')
    return bytes(addresses) + control + pid + info

def create_message_packet(logfile) -> bytes:
    """
    Interactively creates an APRS message packet.
    
    Prompts for:
      - Source call sign (e.g., W7PDJ-10)
      - Destination call sign (e.g., W7PDJ-7)
      - Optional digipeater path (comma-separated, e.g., WIDE2-1,WIDE3-1)
      - Message text
      - Message ID (optional)
    
    The user reviews the human-readable packet and can send, edit, or cancel.
    Returns the binary AX.25 packet ready for KISS encoding.
    """
    source = input("Enter source call sign (e.g., W7PDJ-10): ").strip()
    destination = input("Enter destination call sign (e.g., W7PDJ-7): ").strip()
    digi_input = input("Enter digipeater path (optional, comma-separated, e.g., WIDE2-1): ").strip()
    # Split the digipeaters on comma and remove extra spaces.
    digipeaters = [d.strip() for d in digi_input.split(',')] if digi_input else []
    message_text = input("Enter message text: ").strip()
    msg_id = input("Enter message ID (optional): ").strip()
    
    # Construct human-readable packet for review.
    if digipeaters:
        digi_str = ",".join(digipeaters)
        packet_str = f"{source}>{destination},{digi_str}:{message_text}"
    else:
        packet_str = f"{source}>{destination}:{message_text}"
    if msg_id:
        packet_str += f"{{{msg_id}}}"
    
    while True:
        print("\nConstructed APRS Message Packet:")
        print(f"  Source         : {source}")
        print(f"  Destination    : {destination}")
        print(f"  Digipeater Path: {', '.join(digipeaters) if digipeaters else '(none)'}")
        print(f"  Message Text   : {message_text}")
        print(f"  Message ID     : {msg_id if msg_id else '(none)'}")
        print(f"  Full packet    : {packet_str}\n")
        choice = input("Send this packet (s), edit a field (e), or cancel (c)? ").strip().lower()
        if choice == 's':
            return build_ax25_message_packet(source, destination, digipeaters, message_text, msg_id)
        elif choice == 'c':
            return None
        elif choice == 'e':
            field = input("Which field to edit? (source/destination/digipeaters/message/msgid): ").strip().lower()
            if field == "source":
                source = input("Enter new source call sign: ").strip()
            elif field == "destination":
                destination = input("Enter new destination call sign: ").strip()
            elif field == "digipeaters":
                digi_input = input("Enter new digipeater path (comma-separated, or leave blank for none): ").strip()
                digipeaters = [d.strip() for d in digi_input.split(',')] if digi_input else []
            elif field == "message":
                message_text = input("Enter new message text: ").strip()
            elif field == "msgid":
                msg_id = input("Enter new message ID (or leave blank to remove): ").strip()
            else:
                print("Unknown field. Options: source, destination, digipeaters, message, msgid.")
            if digipeaters:
                digi_str = ",".join(digipeaters)
                packet_str = f"{source}>{destination},{digi_str}:{message_text}"
            else:
                packet_str = f"{source}>{destination}:{message_text}"
            if msg_id:
                packet_str += f"{{{msg_id}}}"
        else:
            print("Invalid option. Please choose 's', 'e', or 'c'.")

def main():
    # Configuration for remote Direwolf KISS interface
    host = "localhost"  # Default host
    port = 8001         # Default port

    # Check for command-line arguments
    if len(sys.argv) > 1:
        host = sys.argv[1]
    if len(sys.argv) > 2:
        port = int(sys.argv[2])

    logfile = open("log.txt", "w")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))
        sock.settimeout(1.0)
        log_message(f"Connected to {host}:{port}", logfile)
    except Exception as e:
        log_message(f"Error connecting to {host}:{port} - {e}", logfile)
        logfile.close()
        return

    # Display an example message packet for reference.
    example_packet = "W7PDJ-10>W7PDJ-7,WIDE2-1:Hello World{1234"
    log_message(f"Example APRS Message Packet: {example_packet}", logfile)

    exit_event = threading.Event()
    receiver_thread = threading.Thread(target=receiver, args=(sock, logfile, exit_event), daemon=True)
    receiver_thread.start()

    try:
        while not exit_event.is_set():
            command = input("\nEnter 'new' to create a message packet, 'list' to show heard stations, or 'exit' to quit: ").strip().lower()
            if command in ['exit', 'quit']:
                exit_event.set()
                break
            elif command == 'new':
                packet_binary = create_message_packet(logfile)
                if packet_binary:
                    kiss_frame = kiss_encode(packet_binary)
                    try:
                        sock.sendall(kiss_frame)
                        log_message(f"Sent: {decode_ax25_packet(packet_binary)}", logfile)
                    except Exception as e:
                        log_message(f"Error sending packet: {e}", logfile)
                        exit_event.set()
                else:
                    log_message("Packet creation cancelled.", logfile)
            elif command == 'list':
                with heard_lock:
                    if heard_stations:
                        print("\nHeard Stations:")
                        for station in sorted(heard_stations.keys()):
                            print(f"  {station}: {heard_stations[station]}")
                    else:
                        print("\nNo stations heard yet.")
            else:
                print("Unknown command. Please enter 'new', 'list', or 'exit'.")
    except KeyboardInterrupt:
        log_message("Exiting on keyboard interrupt.", logfile)
        exit_event.set()
    finally:
        sock.close()
        receiver_thread.join()
        logfile.close()

if __name__ == "__main__":
    main()
