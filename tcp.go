package tcpip

import (
	"math/rand"
)

const (
	TCP_STATE_LISTEN int  = 0
	TCP_STATE_SYNSENT     = 1
	TCP_STATE_SYNRECEIVED = 2
	TCP_STATE_ESTABLISHED = 3
	TCP_STATE_FINWAIT1    = 4
	TCP_STATE_FINWAIT2    = 5
	TCP_STATE_CLOSEWAIT   = 6
	TCP_STATE_CLOSING     = 7
	TCP_STATE_LASTACK     = 8
	TCP_STATE_TIMEWAIT    = 9
	TCP_STATE_CLOSED      = 10

	TCP_FLAG_FIN uint8 = 1
	TCP_FLAG_SYN       = 2
	TCP_FLAG_RST       = 4
	TCP_FLAG_ACK       = 16
	TCP_FLAG_FINACK    = 17
	TCP_FLAG_SYNACK    = 18
	TCP_FLAG_PSHACK    = 24

	MAX_SEQUENCE_NUMBER uint32 = 2^32 - 1
)

type TCPHeader struct {
	TCPFixHeader
	// TDOO: implment Options
}

type TCPFixHeader struct {
	SourcePort           uint16
	DestinationPort      uint16
	SequenceNumber       uint32
	AcknowledgmentNumber uint32
	DataOffsetAndRsrvd   uint8
	Flags                uint8
	Window               uint16
	Checksum             uint16
	UrgentPointer        uint16
}

func(t *TCPFixHeader) Bytes() ([]byte, error) {
	return structToBytes(t)
}

func parseToTCPPacket(bytes []byte) (*TCPPacket, error) {
	h := TCPHeader{}
	if err := bytesToStruct(bytes[0:20], &h); err != nil {
		return nil, err
	}
	offsetBytes := 4 * (h.DataOffsetAndRsrvd >> 4)
	t := TCPPacket {
		Header: h,
		Data: bytes[offsetBytes:],
	}
	return &t, nil
}

type TCPIPv4PseudoHeader struct {
	SourceAddress      [4]byte
	DestinationAddress [4]byte
	Zero               uint8
	PTCL               uint8
	TCPLength          uint16
}

func(t *TCPIPv4PseudoHeader) Bytes() ([]byte, error) {
	return structToBytes(t)
}

type TCPPacket struct {
	Header TCPHeader
	PsudoHeader TCPIPv4PseudoHeader
	Data	 []byte
}

func(t *TCPPacket) Bytes() ([]byte, error) {
	hBytes, err := GetCheckSumedTCPHeaderBytes(&t.PsudoHeader, &t.Header, t.Data)
	if err != nil {
		return nil, err
	}
	return append(hBytes, t.Data...), nil
}

func(t *TCPPacket) setSequenceNumber(n uint32) {
	t.Header.SequenceNumber = n
}

func(t *TCPPacket) setAcknowledgementNumber(n uint32) {
	t.Header.AcknowledgmentNumber = n
}

func(t *TCPPacket) setFlags(f uint8) {
	t.Header.Flags = f
}

func(t *TCPPacket) setData(data []byte) {
	t.Data = data
	t.PsudoHeader.TCPLength += uint16(len(data))
}

func GetTCPPacketTemplate(conn *TCPConnIPv4) *TCPPacket {
	header := TCPFixHeader {
		SourcePort:           conn.socket.srcPort,
		DestinationPort:      conn.dstPort,
		SequenceNumber:       0, // need to set afterward
		AcknowledgmentNumber: 0, // need to set afterward
		DataOffsetAndRsrvd:   5 << 4, // octet of TCP fix header length for now (needs to include options)
		Flags:                0, // need to set afterward
		Window:               10000, // fix value for now
		Checksum:             0,
		UrgentPointer:        0,
	}
	pseudoHeader := TCPIPv4PseudoHeader {
		SourceAddress: conn.socket.srcIPv4,
		DestinationAddress: conn.dstIPv4,
		Zero: 0,
		PTCL: PROTOCOL_TCP,
		TCPLength: 20, // octet of TCP fix header length for now (needs to include options)
	}
	return &TCPPacket {
		TCPHeader{header},
		pseudoHeader,
		[]byte{}, // need to set afterward
	}
}

func GetSynPacket(conn *TCPConnIPv4) *TCPPacket {
	packet := GetTCPPacketTemplate(conn)
	packet.setSequenceNumber(conn.sendState.iss)
	packet.setAcknowledgementNumber(0)
	packet.setFlags(TCP_FLAG_SYN)
	return packet
}

func GetAckPacket(conn *TCPConnIPv4) *TCPPacket {
	packet := GetTCPPacketTemplate(conn)
	packet.setSequenceNumber(conn.sendState.nxt)
	packet.setAcknowledgementNumber(conn.recvState.nxt)
	packet.setFlags(TCP_FLAG_ACK)
	return packet
}

func GetFinAckPacket(conn *TCPConnIPv4) *TCPPacket {
	packet := GetTCPPacketTemplate(conn)
	packet.setSequenceNumber(conn.sendState.nxt)
	packet.setAcknowledgementNumber(conn.recvState.nxt)
	packet.setFlags(TCP_FLAG_FINACK)
	return packet
}

func GetPshAckPacket(conn *TCPConnIPv4, data []byte) *TCPPacket {
	packet := GetTCPPacketTemplate(conn)
	packet.setSequenceNumber(conn.sendState.nxt)
	packet.setAcknowledgementNumber(conn.recvState.nxt)
	packet.setFlags(TCP_FLAG_PSHACK)
	packet.setData(data)
	return packet
}

func GetCheckSumedTCPHeaderBytes(psudo *TCPIPv4PseudoHeader, header *TCPHeader, data []byte) ([]byte, error) {
	psudoBytes, err := structToBytes(psudo)
	if err != nil {
		return nil, err
	}
	headerBytes, err := structToBytes(header)
	if err != nil {
		return nil, err
	}

	checksum := getCheckSum(append(append(psudoBytes, headerBytes...), data...))
	headerBytes[16] = checksum[0]
	headerBytes[17] = checksum[1]
	return headerBytes, nil
}

func getInitialSequenceNumber() uint32 {
	return rand.Uint32()
}
