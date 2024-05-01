# Copyright (c) 2024 Dry Ark LLC
# Anti-Corruption License
import socket
import struct
from cf_iface import get_potential_remoted_ifaces

def decode_labels(message, offset):
    labels = []
    while True:
        length, = struct.unpack_from("!B", message, offset)
        if (length & 0xC0) == 0xC0:  # Pointer to a prior label
            pointer, = struct.unpack_from("!H", message, offset)
            return labels + decode_labels(message, pointer & 0x3FFF)[0], offset + 2
        if length == 0:
            return labels, offset + 1
        offset += 1
        labels.append(*struct.unpack_from(f"!{length}s", message, offset))
        offset += length

def decode_resource_record(message, offset):
    labels, offset = decode_labels(message, offset)
    #name = b".".join(labels).decode()
    type, cls, ttl, rdlength = struct.unpack_from("!HHIH", message, offset)
    offset += 10  # Move past the header part of the resource record
    if type == 12:  # PTR record
        ptr_labels, _ = decode_labels(message, offset)
        ptr_name = b".".join(ptr_labels).decode()
        return (True,ptr_name, offset + rdlength)
    else:
        return (False,"", offset + rdlength)

def response_to_service_names(response):
    transaction_id, flags, questions, ancount, nscount, arcount = struct.unpack_from("!HHHHHH", response, 0)
    offset = 12  # Start after the header
    # Skip over questions
    for _ in range(questions):
        _, offset = decode_labels(response, offset)  # domain name
        offset += 4  # type and class
    
    # Process answer section
    answers = []
    for _ in range(ancount):
        is_ptr, answer, offset = decode_resource_record(response, offset)
        if is_ptr:
            clean = remove_suffix( answer, "._tcp.local" )[1:]
            answers.append(clean)
    return answers

def remove_suffix(input_string, suffix):
    if input_string.endswith(suffix):
        return input_string[:-len(suffix)]
    else:
        return input_string

def get_service_info(iface_name):
    # Set up the socket for IPv6
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    if not isinstance(sock, socket.socket):
            raise RuntimeError("Failed to create socket")
            
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 20)
    
    #print( f'sending mdns query to {iface_name}' )
    iface_index = socket.if_nametoindex(iface_name)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, iface_index)
    
    mdns_addr = ('ff02::fb', 5353) # mDNS IPv6 address and port
    sock.settimeout(0.25)
    
    answerSet = set()
    source_ipv6 = ""
    try:
        dns_header = struct.pack("!HHHHHH", 0x0000, 0x0100, 1, 0, 0, 0) # Standard query
        dns_question = (
            b"\x09_services\x07_dns-sd\x04_udp\x05local\x00"  # the question name
            b"\x00\x0C"  # type PTR
            b"\x00\x01"  # class IN
        )
        sock.sendto(dns_header + dns_question, mdns_addr)
        response, source_address = sock.recvfrom(1024)
        #print( f'got mdns answer from {iface_name}' )
        source_ipv6 = source_address[0]
        answers = response_to_service_names(response)
        for answer in answers:
            answerSet.add( answer )
        #print( f'{iface_name} answers {answers}' )
    except TimeoutError:
        #print( f'timeout getting mdns answer from {iface_name}' )
        pass
    finally:
        sock.close()
    return {
        'services': answerSet,
        'ipv6': source_ipv6,
    }

def get_remoted_interfaces( ios17only: bool ):
    potential_ifaces = get_potential_remoted_ifaces()
    result = []
    for iface in potential_ifaces:
        service_info = get_service_info( iface )
        services = service_info['services']
        if "remoted" in services:
            hasRemotePairing = False
            if "remotepairing" in services:
                hasRemotePairing = True
            if not ios17only or hasRemotePairing:
                result.append({
                    'interface': iface,
                    'ipv6': service_info['ipv6'],
                    'hasRemotePairing': hasRemotePairing,
                })
    return result
