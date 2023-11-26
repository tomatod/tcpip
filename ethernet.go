package tcpip

// https://www.rfc-editor.org/rfc/rfc5342#appendix-B.1
const (
	PROTOCOL_IPV4 uint16 = 0x0800
	PROTOCOL_ARP  uint16 = 0x0806
)

type EthernetHeader struct {
	DstMacAddr   [6]byte
	SrcMacAddr   [6]byte
	ProtocolType uint16
}

type EthernetPacket struct {
	Header *EthernetHeader
	Data   []byte
}

func(e *EthernetHeader) Bytes() ([]byte, error) {
	return structToBytes(e)
}
