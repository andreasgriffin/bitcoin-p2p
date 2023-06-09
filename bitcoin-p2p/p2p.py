import socket
import struct
import time
import hashlib
# https://en.bitcoin.it/wiki/Protocol_documentation#version

debug =False


def decode_varint(data):
    assert len(data) >= 1
    size = int.from_bytes(data[:1], byteorder="little")
    if size < 0xfd:
        return size, 1
    elif size == 0xfd:
        return int.from_bytes(data[1:3], byteorder="little"), 3
    elif size == 0xfe:
        return int.from_bytes(data[1:5], byteorder="little"), 5
    elif size == 0xff:
        return int.from_bytes(data[1:9], byteorder="little"), 9
    else:
        raise ValueError("Invalid varint size.")

        

def double_sha256(payload):
    return hashlib.sha256(hashlib.sha256(payload).digest()).digest()

def receive_exactly(sock, size):
    data = b''
    while len(data) < size:
        more_data = sock.recv(size - len(data))
        if not more_data:
            raise Exception("Connection closed")
        data += more_data
    return data

def get_bitcoin_message(message_type, payload):
    header = struct.pack(">L", 0xF9BEB4D9)
    header += struct.pack("12s", bytes(message_type, 'utf-8'))
    header += struct.pack("<L", len(payload))
    header += double_sha256(payload)[:4]
    return header + payload

def get_version_payload():
    my_ip = '127.0.0.1'  # is is ok for  a non-reachable node

    version = 70014
    services = 1
    timestamp = int(time.time())
    addr_recvservices = 1
    addr_recvipaddress = socket.inet_pton(socket.AF_INET6, f"::ffff:{my_ip}")
    addr_recvport = 8333
    addr_transservices = 1
    addr_transipaddress = socket.inet_pton(socket.AF_INET6, f"::ffff:{my_ip}")
    addr_transport = 8333
    nonce = 0
    user_agentbytes = 0
    start_height = 329167
    relay = 1  # enable receiving txs

    payload = struct.pack("<I", version)
    payload += struct.pack("<Q", services)
    payload += struct.pack("<Q", timestamp)
    payload += struct.pack("<Q", addr_recvservices)
    payload += struct.pack("16s", addr_recvipaddress)
    payload += struct.pack(">H", addr_recvport)
    payload += struct.pack("<Q", addr_transservices)
    payload += struct.pack("16s", addr_transipaddress)
    payload += struct.pack(">H", addr_transport)
    payload += struct.pack("<Q", nonce)
    payload += struct.pack("<B", user_agentbytes)
    payload += struct.pack("<I", start_height)
    payload += struct.pack("<?", relay)

    return payload        
        

def encode_varint(n):
    if n < 0xfd:
        return bytes([n])
    elif n <= 0xffff:
        return b'\xfd' + struct.pack('<H', n)
    elif n <= 0xffffffff:
        return b'\xfe' + struct.pack('<I', n)
    else:
        return b'\xff' + struct.pack('<Q', n)

    

    
def listen(peer, call_back_tx=None, callback_min_feerate=None, callback_header=None, callback_addr=None, callback_inv=None):
    print(f'Connecting to {peer}')
    
    MAGIC_BYTES = bytes.fromhex('F9BEB4D9')

    # Connect to the node
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(60)  # timeout after 60 seconds of inactivity
    s.connect((peer, 8333))  # replace with your node's IP and port


    s.send(get_bitcoin_message("version", get_version_payload()))

    # Listen for incoming messages
    while True:
        if debug:
            print('\nwaiting for message')
        header = receive_exactly(s, 24)
        command = header[4:16].strip(b'\x00').decode()
        payload_length = struct.unpack("I", header[16:20])[0]
        if debug:
            print(f'{peer} command {command}  payload_length {payload_length}')
        if payload_length > 0:
            payload = receive_exactly(s, payload_length)
        else:
            payload = b''

            
        if command == "verack":
            s.send(get_bitcoin_message("verack", b''))
            #s.send(get_bitcoin_message("getaddr", b''))  # ask for addresses after sending verack
            

        elif command == 'sendheaders':
            # No action needed, just print the command
            print("Received sendheaders command")

        elif command == 'version':
            # Respond with verack message
            s.send(get_bitcoin_message("verack", b''))            
        elif command == 'inv':
            count, consumed = decode_varint(payload)  # read varint
            print(f'Inventory count {count}')

            inv_type_hashes = []
            for i in range(count):
                start_index = consumed + i * 36
                end_index = consumed + (i+1) * 36
                if end_index > len(payload):
                    print(f"Received fewer inventory items than expected ({count}).")
                    break
                inv_type = struct.unpack("<I", payload[start_index : start_index + 4])[0]
                if inv_type == 1:  # if the type is TX
                    tx_hash = payload[start_index + 4 : end_index]
                    #print(f'tx_hash {tx_hash[::-1].hex()}')
                    inv_type_hashes.append((inv_type, tx_hash))
            
            # inv_type_hashes is a list of tuples like (inv_type, tx_hash)
            if callback_inv:
                callback_inv(inv_type_hashes)
            
            # Build the getdata payload
            getdata_payload = encode_varint(len(inv_type_hashes))
            for inv_type, tx_hash in inv_type_hashes:
                getdata_payload += struct.pack("<I32s", inv_type, tx_hash)
            s.send(get_bitcoin_message("getdata", getdata_payload))
          
            
        elif command == 'addr':
            count = struct.unpack("B", payload[0:1])[0]  # read varint
            node_addresses = []
            for i in range(count):
                timestamp, = struct.unpack("<I", payload[1 + 30 * i : 5 + 30 * i])
                ip = socket.inet_ntop(socket.AF_INET6, payload[5 + 30 * i : 21 + 30 * i])
                port, = struct.unpack(">H", payload[21 + 30 * i : 23 + 30 * i])
                node_addresses.append((ip, port))
            if callback_addr:   
                callback_addr(node_addresses)
            else:
                print(f"Received addresses: {node_addresses}")

        elif command == 'sendcmpct':
            # Handle sendcmpct message
            print("Received sendcmpct")

        elif command == 'ping':
            # Handle ping message: Respond with a pong message
            print("Received ping")
            nonce = payload[:8]  # nonce is 8 bytes
            s.send(get_bitcoin_message("pong", nonce))

        elif command == 'getheaders':
            # Handle getheaders message
            print("Received getheaders")

        elif command == 'feefilter':
            # Handle feefilter message
            feerate, = struct.unpack("<Q", payload)
            if callback_min_feerate:
                callback_min_feerate(feerate)
            else:
                print(f"Received feefilter, minimum feerate is {feerate}")
            

        elif command == 'tx':
            if call_back_tx:
                call_back_tx(payload)
            else:
                tx_hash = double_sha256()[::-1].hex()
                print("Received transaction:", tx_hash)            

        elif command == 'headers':
            count, consumed = decode_varint(payload)  # read varint
            print(f'Header count {count}')

            for i in range(count):
                start_index = consumed + i * 81
                end_index = consumed + (i + 1) * 81
                if end_index > len(payload):
                    print(f"Received fewer headers than expected ({count}).")
                    break
                header = payload[start_index:end_index]
                # Process the header as needed
                if callback_header:
                    callback_header(header)
                else:
                    print(f'Header {i+1}: {header.hex()}')
        else:
            
            print(f'unknown command {command}')





def get_bitcoin_peer():
    # use a dns request to a seed bitcoin DNS server to find a node
    nodes = socket.getaddrinfo("seed.bitcoin.sipa.be", None)

    # arbitrarily choose the first node
    return nodes[-1][4][0]





