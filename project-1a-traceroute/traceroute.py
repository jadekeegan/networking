import util

# Your program should send TTLs in the range [1, TRACEROUTE_MAX_TTL] inclusive.
# Technically IPv4 supports TTLs up to 255, but in practice this is excessive.
# Most traceroute implementations cap at approximately 30.  The unit tests
# assume you don't change this number.
TRACEROUTE_MAX_TTL = 30

# Cisco seems to have standardized on UDP ports [33434, 33464] for traceroute.
# While not a formal standard, it appears that some routers on the internet
# will only respond with time exceeeded ICMP messages to UDP packets send to
# those ports.  Ultimately, you can choose whatever port you like, but that
# range seems to give more interesting results.
TRACEROUTE_PORT_NUMBER = 33434  # Cisco traceroute port number.

# Sometimes packets on the internet get dropped.  PROBE_ATTEMPT_COUNT is the
# maximum number of times your traceroute function should attempt to probe a
# single router before giving up and moving on.
PROBE_ATTEMPT_COUNT = 3

class IPv4:
    # Each member below is a field from the IPv4 packet header.  They are
    # listed below in the order they appear in the packet.  All fields should
    # be stored in host byte order.
    #
    # You should only modify the __init__() method of this class.
    version: int
    header_len: int  # Note length in bytes, not the value in the packet.
    tos: int         # Also called DSCP and ECN bits (i.e. on wikipedia).
    length: int      # Total length of the packet.
    id: int
    flags: int
    frag_offset: int
    ttl: int
    proto: int
    cksum: int
    src: str
    dst: str

    def __init__(self, buffer: bytes):
        # Parse IPv4 header from the provided buffer.
        b = bytesToBitstring(buffer[0:20])  # IPv4 header is 20 bytes long.

        self.version = bitstringToInt(b[0:4])               # 4 bits for version
        # convert to bytes since packet length has it in 32-bit words
        # ex: four 4-byte words = 16 bytes total
        self.header_len     = bitstringToInt(b[4:8]) * 4    # 4 bits for header length
        self.tos            = bitstringToInt(b[8:16])       # 8 bits for type of service
        self.length         = bitstringToInt(b[16:32])      # 16 bits for total length
        self.id             = bitstringToInt(b[32:48])      # 16 bits for identification
        self.flags          = bitstringToInt(b[48:51])      # 3 bits for flags
        self.frag_offset    = bitstringToInt(b[51:64])      # 13 bits for fragment offset
        self.ttl            = bitstringToInt(b[64:72])      # 8 bits for time to live
        self.proto          = bitstringToInt(b[72:80])      # 8 bits for protocol
        self.cksum          = bitstringToInt(b[80:96])      # 16 bits for checksum
        # Source and destination IP addresses are 32 bits each, split into four 8-bit segments
        # and convert to decimal dotted notation.
        self.src = '.'.join(str(bitstringToInt(b[i:i+8])) for i in range(96, 128, 8))
        self.dst = '.'.join(str(bitstringToInt(b[i:i+8])) for i in range(128, 160, 8))

    def __str__(self) -> str:
        return f"IPv{self.version} (tos 0x{self.tos:x}, ttl {self.ttl}, " + \
            f"id {self.id}, flags 0x{self.flags:x}, " + \
            f"ofsset {self.frag_offset}, " + \
            f"proto {self.proto}, header_len {self.header_len}, " + \
            f"len {self.length}, cksum 0x{self.cksum:x}) " + \
            f"{self.src} > {self.dst}"


class ICMP:
    # Each member below is a field from the ICMP header.  They are listed below
    # in the order they appear in the packet.  All fields should be stored in
    # host byte order.
    #
    # You should only modify the __init__() function of this class.
    type: int
    code: int
    cksum: int

    def __init__(self, buffer: bytes):
        b = bytesToBitstring(buffer[20:24])  # ICMP header is 8 bytes long.
        self.type   = bitstringToInt(b[0:8])        # 8 bits for type
        self.code   = bitstringToInt(b[8:16])       # 8 bits for code
        self.cksum  = bitstringToInt(b[16:32])      # 16 bits for checksum

    def __str__(self) -> str:
        return f"ICMP (type {self.type}, code {self.code}, " + \
            f"cksum 0x{self.cksum:x})"


class UDP:
    # Each member below is a field from the UDP header.  They are listed below
    # in the order they appear in the packet.  All fields should be stored in
    # host byte order.
    #
    # You should only modify the __init__() function of this class.
    src_port: int
    dst_port: int
    len: int
    cksum: int

    def __init__(self, buffer: bytes):
        b = bytesToBitstring(buffer[48:64])           # UDP header is 8 bytes long.
        self.src_port  = bitstringToInt(b[0:16])      # 16 bits for source port
        self.dst_port  = bitstringToInt(b[16:32])     # 16 bits for destination port
        self.len       = bitstringToInt(b[32:48])     # 16 bits for length
        self.cksum     = bitstringToInt(b[48:64])     # 16 bits for checksum

    def __str__(self) -> str:
        return f"UDP (src_port {self.src_port}, dst_port {self.dst_port}, " + \
            f"len {self.len}, cksum 0x{self.cksum:x})"

# Helper Functions
def bytesToBitstring(buffer: bytes) -> str:
    """ Convert a bytes object to a bitstring. """
    return ''.join(format(byte, '08b') for byte in [*buffer])

def bitstringToInt(bitstring: str) -> int:
    """ Convert a bitstring to an integer. """
    return int(bitstring, 2)

def printPacketInfo(buffer: bytes, address: tuple[str, int]) -> None:
    """ Print the information of the packet. """
    print(f"Packet bytes: {buffer.hex()}")
    print(f"Packet is from IP: {address[0]}")
    print(f"Packet is from port: {address[1]}")

def printHeaderInfo(buffer: bytes) -> None:
    """ Print the header information of the packet. """
    ipv4 = IPv4(buffer)
    icmp = ICMP(buffer)
    udp = UDP(buffer)

    print(f"IPv4 Header: {IPv4.__str__(ipv4)}")
    print(f"ICMP Header: {ICMP.__str__(icmp)}")
    print(f"UDP Header: {UDP.__str__(udp)}")

def sendPacket(sendsock: util.Socket, ip: str, ttl: int, msg: str) -> None:
    """ Send a packet with the specified TTL. """
    sendsock.set_ttl(ttl)
    sendsock.sendto(msg.encode(), (ip, TRACEROUTE_PORT_NUMBER))


def traceroute(sendsock: util.Socket, recvsock: util.Socket, ip: str) \
        -> list[list[str]]:
    """ Run traceroute and returns the discovered path.

    Calls util.print_result() on the result of each TTL's probes to show
    progress.

    Arguments:
    sendsock -- This is a UDP socket you will use to send traceroute probes.
    recvsock -- This is the socket on which you will receive ICMP responses.
    ip -- This is the IP address of the end host you will be tracerouting.

    Returns:
    A list of lists representing the routers discovered for each ttl that was
    probed.  The ith list contains all of the routers found with TTL probe of
    i+1.   The routers discovered in the ith list can be in any order.  If no
    routers were found, the ith list can be empty.  If `ip` is discovered, it
    should be included as the final element in the list.
    """

    sendPacket(sendsock, ip, ttl = 1, msg = "Hello World")

    if recvsock.recv_select(): # check if there is a packet ready to be received
        buf, address = recvsock.recvfrom() # receive the packet

        printPacketInfo(buf, address)
        printHeaderInfo(buf)
        


if __name__ == '__main__':
    args = util.parse_args()
    ip_addr = util.gethostbyname(args.host)
    print(f"traceroute to {args.host} ({ip_addr})")
    traceroute(util.Socket.make_udp(), util.Socket.make_icmp(), ip_addr)
