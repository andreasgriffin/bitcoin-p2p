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



def decode_version_payload(payload):
    services_map = {
        0: {'name': 'NODE_NETWORK', 'description': 'This node can be asked for full blocks instead of just headers.'},
        1: {'name': 'NODE_GETUTXO', 'description': 'See BIP 0064: https://github.com/bitcoin/bips/blob/master/bip-0064.mediawiki'},
        2: {'name': 'NODE_BLOOM', 'description': 'See BIP 0111: https://github.com/bitcoin/bips/blob/master/bip-0111.mediawiki'},
        3: {'name': 'NODE_WITNESS', 'description': 'See BIP 0144: https://github.com/bitcoin/bips/blob/master/bip-0144.mediawiki'},
        4: {'name': 'NODE_XTHIN', 'description': 'Never formally proposed (as a BIP), and discontinued. Was historically sporadically seen on the network.'},
        6: {'name': 'NODE_COMPACT_FILTERS', 'description': 'See BIP 0157: https://github.com/bitcoin/bips/blob/master/bip-0157.mediawiki'},
        10: {'name': 'NODE_NETWORK_LIMITED', 'description': 'See BIP 0159: https://github.com/bitcoin/bips/blob/master/bip-0159.mediawiki'}
    }

    version, services, timestamp = struct.unpack_from("<IQQ", payload, 0)
    decoded_services = []
    for bit, service in services_map.items():
        if services & (1 << bit):
            decoded_service = service.copy()
            decoded_service['value'] = True
            decoded_services.append(decoded_service)
    
    addr_recvservices, = struct.unpack_from("<Q", payload, 20)
    addr_recvipaddress = struct.unpack_from("16s", payload, 28)[0]
    addr_recvipaddress = socket.inet_ntop(socket.AF_INET6, addr_recvipaddress)
    addr_recvport, = struct.unpack_from(">H", payload, 44)
    addr_transservices, = struct.unpack_from("<Q", payload, 46)
    addr_transipaddress = struct.unpack_from("16s", payload, 54)[0]
    addr_transipaddress = socket.inet_ntop(socket.AF_INET6, addr_transipaddress)
    addr_transport, = struct.unpack_from(">H", payload, 70)
    nonce, = struct.unpack_from("<Q", payload, 72)

    user_agentbytes, varint_len = decode_varint(payload[80:])
    user_agent = payload[80 + varint_len:80 + varint_len + user_agentbytes].decode()
    start_height, = struct.unpack_from("<I", payload, 80 + varint_len + user_agentbytes)
    relay, = struct.unpack_from("<?", payload, 84 + varint_len + user_agentbytes)

    result = {
        'version': version,
        'services': services,
        'services_list':[service['name'] for service in decoded_services],
        'decoded_services': decoded_services,
        'timestamp': timestamp,
        'addr_recvservices': addr_recvservices,
        'addr_recvipaddress': addr_recvipaddress,
        'addr_recvport': addr_recvport,
        'addr_transservices': addr_transservices,
        'addr_transipaddress': addr_transipaddress,
        'addr_transport': addr_transport,
        'nonce': nonce,
        'user_agentbytes': user_agentbytes,
        'user_agent': user_agent,
        'start_height': start_height,
        'relay': relay,
    }

    return result


    
def process_command(s,
                    fetch_txs=True,
                    call_back_tx=None, 
                    callback_min_feerate=None, 
                    callback_header=None, 
                    callback_addr=None, 
                    callback_inv=None,
                    callback_version=None):

    if debug:
        print('\nwaiting for message')
    header = receive_exactly(s, 24)
    command = header[4:16].strip(b'\x00').decode()
    payload_length = struct.unpack("I", header[16:20])[0]
    if debug:
        print(f'command {command}  payload_length {payload_length}')
    if payload_length > 0:
        payload = receive_exactly(s, payload_length)
    else:
        payload = b''

        
    if command == "verack":
        s.send(get_bitcoin_message("verack", b''))
        

    elif command == 'sendheaders':
        # No action needed, just print the command
        print("Received sendheaders command")

    elif command == 'version':
        version_data = decode_version_payload(payload)

        if not callback_version:
            print(f"version data {version_data}")            
        else:
            callback_version(version_data)
        
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
        
        
        if fetch_txs:
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
            tx_hash = double_sha256(payload)[::-1].hex()
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




def create_socket_connection(peer, timeout=60):
    print(f'Connecting to {peer}')

    # Connect to the node
    if isinstance(peer, (list, tuple)):
        s = socket.socket(peer[1], peer[2])
        peer_ip = peer[0]
    else:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        peer_ip = peer
    
    s.settimeout(timeout)  # timeout after 60 seconds of inactivity
    s.connect((peer_ip, 8333))  # replace with your node's IP and port
    print(f'Success. Connected to {peer}')

    s.send(get_bitcoin_message("version", get_version_payload()))
    return s    
    



def listen(peer, 
           fetch_txs=True,
           call_back_tx=None, 
           callback_min_feerate=None, 
           callback_header=None, 
           callback_addr=None, 
           callback_inv=None,
           callback_version=None,
           f_continue_listening=lambda:True,
           timeout=60):



    try:
        s = create_socket_connection(peer, timeout=timeout)
        print('socket connection created')
        # Listen for incoming messages
        while f_continue_listening():
            process_command(s, fetch_txs=fetch_txs, call_back_tx=call_back_tx,
                            callback_min_feerate=callback_min_feerate, callback_header=callback_header,
                            callback_addr=callback_addr, callback_inv=callback_inv, callback_version=callback_version)
    except TimeoutError:
        print('timeout')
    except OSError:
        print('OSError')
    finally:
        if 's' in globals():
            s.close()
            print('Connection closed')






def get_bitcoin_peers():
    # dns_seeds = [
    #     'bitcoin.jonasschnelli.ch',
    #     'seed.btc.petertodd.org',
    #     'seed.bluematt.me',
    #     'seed.bitcoin.schildbach.de',
    #     'seed.bitcoin.sipa.be',
    # ]
    
    # use a dns request to a seed bitcoin DNS server to find a node
    nodes = socket.getaddrinfo("seed.bitcoin.sipa.be", None)

    # arbitrarily choose the last node
    peers = [(node[4][0], node[0], node[1]) for node in nodes if node[1] in [socket.SocketKind.SOCK_STREAM]]
    return peers[::-1]




def get_bitcoin_peer():
    return get_bitcoin_peers()[0]






def get_cbf_node():
    def callback_version(version_data):
        nonlocal continue_listening
        nonlocal is_cbf
        continue_listening = False        
        is_cbf =  'NODE_COMPACT_FILTERS' in version_data["services_list"]
        if debug:
            print(version_data)
            print(f'is_cbf = {is_cbf}')
    def f_continue_listening():
        nonlocal continue_listening
        return continue_listening
    
    is_cbf = False
    while not is_cbf:
        peers = get_bitcoin_peers()
        for i, peer in enumerate(peers):
            if debug:
                print(f'Try peer {i}/{len(peers)}')
            continue_listening = True
            listen(peer, callback_version=callback_version, f_continue_listening=f_continue_listening, timeout=5)
            if is_cbf:
                return peer   
            