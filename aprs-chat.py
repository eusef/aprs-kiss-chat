#!/usr/bin/env python3
import socket
import threading
import sys
from kiss_utils import *
from ax25_utils import *

# Global locks and dictionary for heard stations
log_lock = threading.Lock()
heard_lock = threading.Lock()
heard_stations = {}  # Maps station call sign -> most recent packet (human-readable)

# Global flag to pause logging
pause_logging = threading.Event()

def log_message(message: str, logfile) -> None:
    """
    Logs a message to the console and the log file.
    If highlight is True, the message is highlighted with a green background and black text.
    """
    with log_lock:
        if not pause_logging.is_set():
            print("\n" + message)  # Add newline before message
        logfile.write(message + "\n")
        logfile.flush()

def build_ack_packet(source: str, destination: str, msg_id: str) -> bytes:
    """
    Builds an AX.25 acknowledgement packet.
    """
    ack_text = f"ack{msg_id}"
    return build_ax25_message_packet(source, destination, [], ack_text, "")

def receiver(sock: socket.socket, logfile, exit_event: threading.Event, default_source: str) -> None:
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
                # Check if the packet is addressed to the default source and contains a message ID
                if len(addresses) > 0 and addresses[0] == default_source:
                    msg_id_start = decoded_str.find("{")
                    msg_id_end = decoded_str.find("}")
                    if msg_id_start != -1 and msg_id_end != -1:
                        msg_id = decoded_str[msg_id_start+1:msg_id_end]
                        log_message(f"Preparing to send ACK for message ID: {msg_id}", logfile)
                        ack_packet = build_ack_packet(default_source, source, msg_id)
                        kiss_frame = kiss_encode(ack_packet)
                        try:
                            sock.sendall(kiss_frame)
                            log_message(f"Sent ACK: {decode_ax25_packet(ack_packet)}", logfile)
                        except Exception as e:
                            log_message(f"Error sending ACK: {e}", logfile)
            except Exception as e:
                log_message(f"Error processing received packet: {e}", logfile)

def create_message_packet(logfile, default_source: str = "") -> bytes:
    """
    Interactively creates an APRS message packet.
    
    Prompts for:
      - Source call sign (e.g., W7PDJ-10) if not provided as default_source
      - Destination call sign (e.g., W7PDJ-7)
      - Optional digipeater path (comma-separated, e.g., WIDE2-1,WIDE3-1)
      - Message text
      - Message ID (optional)
    
    The user reviews the human-readable packet and can send, edit, or cancel.
    Returns the binary AX.25 packet ready for KISS encoding.
    """
    pause_logging.set()  # Pause logging
    if default_source:
        use_default = input(f"Use default source call sign '{default_source}'? (y/n): ").strip().lower()
        if use_default == 'y':
            source = default_source
        else:
            source = input("Enter source call sign (e.g., W7PDJ-10): ").strip()
    else:
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
            pause_logging.clear()  # Resume logging
            return build_ax25_message_packet(source, destination, digipeaters, message_text, msg_id)
        elif choice == 'c':
            pause_logging.clear()  # Resume logging
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
    default_source = "" # Default source callsign

    # Check for command-line arguments
    if len(sys.argv) > 1:
        host = sys.argv[1]
    if len(sys.argv) > 2:
        port = int(sys.argv[2])
    if len(sys.argv) > 3:
        default_source = sys.argv[3]

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
    receiver_thread = threading.Thread(target=receiver, args=(sock, logfile, exit_event, default_source), daemon=True)
    receiver_thread.start()

    try:
        while not exit_event.is_set():
            command = input("\nEnter 'new' to create a message packet, 'list' to show heard stations, or 'exit' to quit: ").strip().lower()
            if command in ['exit', 'quit']:
                exit_event.set()
                break
            elif command == 'new':
                packet_binary = create_message_packet(logfile, default_source)
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
