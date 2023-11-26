package tcpip

import (
	"syscall"
	"net"
	"context"
	"time"
	"sync"
	"fmt"
)

const (
	MTU int = 1500 // Now, fixed value.
	ETHERNET_HEADER_SIZE int = 14
	IPV4_HEADER_SIZE     int = 20
)

type EtherSocket struct {
	fd            int
	networkIfName string
	macAddr       [6]byte
	protocol      uint16
}

func GetEtherSocket(networkIfName string, protocol uint16) (*EtherSocket, error) {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		return nil, err
	}

	// TODO: try implemention without net package.
	inf, err := net.InterfaceByName(networkIfName)
	if err != nil {
		return nil, err
	}
	if networkIfName == "lo" {
		inf.HardwareAddr = []byte{0, 0, 0, 0, 0, 0}
	}
	sockaddr := syscall.SockaddrLinklayer{
		Protocol: htons(syscall.ETH_P_ALL),
		Halen:    6,
		Addr:     *(*[8]byte)(append(inf.HardwareAddr, 0, 0)),
		Ifindex:  inf.Index,
	}

	if err = syscall.Bind(fd, &sockaddr); err != nil {
		return nil, err
	}

	return &EtherSocket{
		fd: fd,
		networkIfName: networkIfName,
		macAddr: *(*[6]byte)(inf.HardwareAddr),
		protocol: protocol,
	}, nil
}

func(s *EtherSocket) Write(dstMacAddr [6]byte, payload []byte) (int, error) {
	header := &EthernetHeader {
		DstMacAddr: dstMacAddr,
		SrcMacAddr: s.macAddr,
		ProtocolType: s.protocol,
	}
	hBytes, err := header.Bytes()
	if err != nil {
		return 0, err
	}
	return syscall.Write(s.fd, append(hBytes, payload...))
}

func(s *EtherSocket) Read() (*EthernetPacket, error) {
	// TODO: Other of Ethernet for example Wifi.
	frameHeaderSize := ETHERNET_HEADER_SIZE
	data := make([]byte, frameHeaderSize + MTU)
	for {
		length, _, err := syscall.Recvfrom(s.fd, data, 0)
		if err != nil {
			return nil, err
		}
		ptype := uint16(data[12]) << 8 + uint16(data[13])
		if s.protocol != 0 && ptype != s.protocol {
			continue
		}
		header := EthernetHeader{}
		return &EthernetPacket{
			Header: &header,
			Data:   data[:length][frameHeaderSize:],
		}, bytesToStruct(data[:frameHeaderSize], &header)
	}
}

type IPv4Socket struct {
	EtherSocket
	srcIPv4 [4]byte
	protocol uint8
	gatewayIP [4]byte
}

func NewIPv4Socket(networkIfName string, protocol uint8) (*IPv4Socket, error) {
	es, err := GetEtherSocket(networkIfName, PROTOCOL_IPV4)
	if err != nil {
		return nil, err
	}

	var ipv4 [4]byte
	if specified, exist := iPv4AddrByNIC[networkIfName]; exist {
		ipv4 = specified
	} else {
		ipv4, err = getNicIPAddress(networkIfName)
		if err != nil {
			return nil, err
		}
	}

	_, err = staticArpTables.getArpTableByIf(networkIfName)
	if err != nil {
		return nil, err
	}

	gatewayIP, err := getDefaultGateway(networkIfName)
	if err != nil {
		debugf("[socket] default gateway cannot find with error '%v'", err)
	}
	debugf("[socket] default gateway is %v", gatewayIP)

	return &IPv4Socket {
		EtherSocket: *es,
		srcIPv4: ipv4,
		protocol: protocol,
		gatewayIP: gatewayIP,
	}, nil
}

func(s *IPv4Socket) Read() (*IPv4Packet, error) {
	for {
		packet, err := s.EtherSocket.Read()
		if err != nil {
			return nil, err
		}
		header, err := parseIPHeaderFromBytes(packet.Data[0:20])
		if err != nil {
			return nil, err
		}
		if s.protocol != 0 && header.Protocol != s.protocol {
			continue
		}
		if s.srcIPv4 != header.DestinationAddress {
			continue
		}
		ihl := int(packet.Data[0] & 0x0F) * 4

		return &IPv4Packet {
			Header: header,
			Data:   packet.Data[ihl:],
		}, nil
	}
}

func(s *IPv4Socket) Write(dstIPAddr [4]byte, payload []byte) (int, error) {
	hBytes, err := GetIPv4HeaderBytes(uint16(len(payload)), s.protocol, s.srcIPv4, dstIPAddr)
	if err != nil {
		return 0, err
	}
	ctx, _ := context.WithDeadline(context.Background(), time.Now().Add(5 * time.Second))
	dstMac, err := Arpping(ctx, s.EtherSocket.networkIfName, dstIPAddr)
	if err != nil {
		return 0, fmt.Errorf("couldn't find MAC address for", dstIPAddr)
	}
	return s.EtherSocket.Write(dstMac, append(hBytes, payload...))
}

// Now only IPv4
type TCPSocket struct {
	IPv4Socket
	isServer   bool
	srcPort    uint16
	connsIPv4 *TCPConnsIPv4
	loopErr    chan error
}

func NewTCPSocketIPv4(networkIfName string, isServer bool, srcPort uint16) (*TCPSocket, error) {
	ipSocket, err := NewIPv4Socket(networkIfName, PROTOCOL_TCP)
	if err != nil {
		return nil, err
	}
	// start ICMP routine because some functions of TCP use ICMP
	// if _, err = staticIcmpManagers.getManagerByNic(networkIfName); err != nil {
	//	return nil, err
	// }
	s := &TCPSocket {
		IPv4Socket: *ipSocket,
		isServer: isServer,
		srcPort: srcPort,
		connsIPv4: &TCPConnsIPv4{m: map[int]*TCPConnIPv4{}},
		loopErr: make(chan error, 1),
	}
	go s.startLoop()
	return s, nil
}

func(t *TCPSocket) startLoop() {
	for {
		ipPacket, err := t.IPv4Socket.Read()
		if err != nil {
			t.loopErr <- err
			return
		}
		tcpPacket, err := parseToTCPPacket(ipPacket.Data)
		if err != nil {
			debugf("[socket] TCPSocket Cannnot Parse incomming packet with %v", err)
			continue
		}
		conn := t.connsIPv4.getConn(ipPacket.Header.SourceAddress, tcpPacket.Header.SourcePort)
		conn.addRecvBuf(tcpPacket)
	}
}

type TCPConnsIPv4 struct {
	sync.RWMutex
	m map[int]*TCPConnIPv4 // key is zero(0-1th bit) port(2-3th bit) and dstip(4-7th bit)
}

func(t *TCPConnsIPv4) getConn(ip [4]byte, port uint16) *TCPConnIPv4 {
	key := t.calculateKey(ip, port)
	t.RLock()
	defer t.RUnlock()
	return t.m[key]
}

func(t *TCPConnsIPv4) createConn(socket *TCPSocket, ip [4]byte, port uint16) *TCPConnIPv4 {
	key := t.calculateKey(ip, port)
	t.Lock()
	defer t.Unlock()
	t.m[key] = &TCPConnIPv4{
		dstIPv4: ip,
		dstPort: port,
		connState: TCP_STATE_CLOSED,
		sendState: tcpSndStateIPv4{},
		recvState: tcpRcvStateIPv4{},
		sendBuf: []*TCPPacket{},
		recvBuf: []*TCPPacket{},
		sendSig: make(chan bool, 1),
		recvSig: make(chan bool, 1),
		readBuf: []byte{},
		readSig: make(chan bool, 1),
		socket: socket,
		loopErr: make(chan error, 1),
	}
	return t.m[key]
}

func(t *TCPConnsIPv4) calculateKey(ip [4]byte, port uint16) int {
	var key int = 0
	for i, v := range ip {
		key += int(v) << 7-i
	}
	key += int(port) << 2
	return key
}

type TCPConnIPv4 struct {
	sync.RWMutex
	dstIPv4   [4]byte
	dstPort   uint16
	connState int
	sendState tcpSndStateIPv4
	recvState tcpRcvStateIPv4
	sendBuf   []*TCPPacket
	recvBuf   []*TCPPacket
	readBuf   []byte // store data, which is read by high layer application, ordered by sequence number.
	readHead  int    // sequence number which of packet should be read by high layer application next time.
	sendSig   chan bool
	recvSig   chan bool
	readSig   chan bool
	loopErr   chan error
	socket   *TCPSocket
}

func NewTCPClientConnIPv4(networkIfName string, dstIPv4 [4]byte, dstPort uint16) (*TCPConnIPv4, error) {
	srcPort, err := getNewEphemeralPort()
	if err != nil {
		return nil, err
	}
	s, err := NewTCPSocketIPv4(networkIfName, false, srcPort)
	if err != nil {
		return nil, err
	}
	conn := s.connsIPv4.createConn(s, dstIPv4, dstPort)
	if err := conn.start(); err != nil {
		return nil, err
	}
	return conn, nil
}

func (t *TCPConnIPv4) setConnState(state int) {
	t.Lock()
	defer t.Unlock()
	t.connState = state
}

func (t *TCPConnIPv4) addRecvBuf(packet *TCPPacket) {
	t.Lock()
	defer t.Unlock()
	t.recvBuf = append(t.recvBuf, packet)
	if len(t.recvSig) == 0 {
		t.recvSig <- true
	}
}

func (t *TCPConnIPv4) addSendBuf(packet *TCPPacket) {
	t.Lock()
	defer t.Unlock()
	t.sendBuf = append(t.sendBuf, packet)
	if len(t.sendSig) == 0 {
		t.sendSig <- true
	}
}

// func (t *TCPConnIPv4) addReadBuf(seqNum uint32, data []byte) error {
func (t *TCPConnIPv4) addReadBuf(seqNum uint32, data []byte) {
	intSeqNum := int(seqNum)
	t.Lock()
	defer t.Unlock()

	// receive first data
	if t.readHead == 0 {
		t.readHead = intSeqNum
	}

	// wirte data to read buffer read by high level application, considering packet order.
	offset := intSeqNum - t.readHead
	shortage := (offset+len(data)) - len(t.readBuf)
	if shortage > 0 {
		t.readBuf = append(t.readBuf, make([]byte, shortage)...)
	}
	t.readBuf = append(append(t.readBuf[:offset], data...), t.readBuf[offset+len(data):]...)

	if intSeqNum == t.readHead && len(t.readSig) == 0 {
		t.readSig <- true
	}
}

func (t *TCPConnIPv4) readSendPacket() *TCPPacket {
	if len(t.sendBuf) == 0 || len(t.sendSig) != 0 {
		<-t.sendSig
	}
	packet := t.sendBuf[0]
	t.sendBuf = t.sendBuf[1:]
	return packet
}

func (t *TCPConnIPv4) readRecvPacket() *TCPPacket {
	if len(t.recvBuf) == 0 || len(t.recvSig) != 0 {
		<-t.recvSig
	}
	packet := t.recvBuf[0]
	t.recvBuf = t.recvBuf[1:]
	return packet
}

func (t *TCPConnIPv4) startSendLoop() {
	for {
		packet := t.readSendPacket()

		packetBytes, err := packet.Bytes()
		if err != nil {
			t.loopErr <- err
			break
		}
		if _, err := t.socket.IPv4Socket.Write(t.dstIPv4, packetBytes); err != nil {
			t.loopErr <- err
			break
		}

		// after send final ACK of 3-way handshake as client
		if t.connState == TCP_STATE_SYNSENT {
			t.setConnState(TCP_STATE_ESTABLISHED)
			t.loopErr <- nil
			debug("[socket] 3 way handshake is successful")
			continue
		}

		// after sending SYN as client
		if t.connState == TCP_STATE_CLOSED {
			t.setConnState(TCP_STATE_SYNSENT)
			t.sendState.una = t.sendState.iss + 1
			t.sendState.nxt = t.sendState.una
			continue
		}

		if t.connState == TCP_STATE_ESTABLISHED && packet.Header.Flags == TCP_FLAG_FINACK {
			t.setConnState(TCP_STATE_FINWAIT1)
			t.sendState.nxt += 1
		}

		t.sendState.nxt = t.sendState.nxt + uint32(len(packet.Data))
	}
}

// TODO: retransmission
func (t *TCPConnIPv4) startRecvLoop() {
	for {
		packet := t.readRecvPacket()

		// update UNA of receive state
		if packet.Header.AcknowledgmentNumber >= t.sendState.una {
			t.sendState.una = packet.Header.AcknowledgmentNumber
		}

		// when receiving SYN-ACK
		if t.connState == TCP_STATE_SYNSENT {
			if packet.Header.Flags != TCP_FLAG_SYNACK {
				continue
			}
			t.recvState.irs = packet.Header.SequenceNumber
			t.recvState.nxt = t.recvState.irs + 1
			t.addSendBuf(GetAckPacket(t))
			continue
		}

		// when receiving active FIN-ACK
		if t.connState == TCP_STATE_ESTABLISHED && packet.Header.Flags == TCP_FLAG_FINACK {
			// TODO: send FIN-ACK
		}

		// when receiving ACK or passive FIN-ACK after sending active FIN-ACK
		if t.connState == TCP_STATE_FINWAIT1 {
			if packet.Header.Flags == TCP_FLAG_ACK {
				t.setConnState(TCP_STATE_FINWAIT2)
				continue
			}
			if packet.Header.Flags == TCP_FLAG_FINACK {
				// TODO: not immediately close and wait unreceived packets
				// t.setConnState(TCP_STATE_TIMEWAIT)
				t.setConnState(TCP_STATE_CLOSED) // this must wait complication of send ACK.
				if t.recvState.nxt == packet.Header.SequenceNumber {
					t.recvState.nxt = packet.Header.SequenceNumber + 1
				}
				t.addSendBuf(GetAckPacket(t))
				continue
			}
		}

		if len(packet.Data) == 0 {
			continue
		}

		// TODO: consider when packets order is exchanged or packets is lost
		if t.recvState.nxt == packet.Header.SequenceNumber {
			t.recvState.nxt = packet.Header.SequenceNumber + uint32(len(packet.Data))
		}

		// send ACK
		t.addSendBuf(GetAckPacket(t))
		t.addReadBuf(packet.Header.SequenceNumber, packet.Data)
	}
}

func (t *TCPConnIPv4) start() error {
	// start main loops
	go t.startSendLoop()
	go t.startRecvLoop()

	// make and send SYN
	t.sendState.iss = getInitialSequenceNumber()
	t.addSendBuf(GetSynPacket(t))

	return <-t.loopErr
}

// TODO: error handling
func (t *TCPConnIPv4) Write(data []byte) error {
	t.addSendBuf(GetPshAckPacket(t, data))
	return nil
}

// TODO: error handling
func (t *TCPConnIPv4) Read() ([]byte, error) {
	// if t.readBuf.Len() == 0 || len(t.readSig) != 0 {
	if len(t.readBuf) == 0 || len(t.readSig) != 0 {
		<-t.readSig
	}
	t.Lock()
	defer t.Unlock()
	offset := int(t.recvState.nxt) - t.readHead
	if len(t.readBuf) < offset {
		offset = len(t.readBuf)
	}
	b := t.readBuf[:offset]
	t.readBuf = t.readBuf[offset:]
	return b, nil
}

func(t *TCPConnIPv4) Close() error {
	t.addSendBuf(GetFinAckPacket(t))
	return nil
}

// spec: https://datatracker.ietf.org/doc/html/rfc9293#section-3.3.1 -> table 2
type tcpSndStateIPv4 struct {
	sync.RWMutex
	una uint32
	nxt uint32
	wnd uint32
	up  uint32
	wl1 uint32
	wl2 uint32
	iss uint32
}

// spec: https://datatracker.ietf.org/doc/html/rfc9293#section-3.3.1 -> table 3
type tcpRcvStateIPv4 struct {
	sync.RWMutex
	nxt uint32
	wnd uint32
	up  uint32
	irs uint32
}
