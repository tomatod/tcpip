package tcpip

import (
	"math/rand"
)

const (
	PROTOCOL_ICMP uint8 = 0x01
	PROTOCOL_TCP  uint8 = 0x06
	PROTOCOL_UDP  uint8 = 0x11
)

type IPv4Header struct {
	VersionAndIHL          uint8
	TypeOfService          uint8
	TotalLength            uint16
	Identification         uint16
	FlagsAndFragmentOffset uint16
	TimeToLive             uint8
	Protocol               uint8
	HeaderCheckSum         uint16
	SourceAddress         [4]byte
	DestinationAddress    [4]byte
}

func(i *IPv4Header) Bytes() ([]byte, error) {
	return structToBytes(i)
}

func parseIPHeaderFromBytes(bytes []byte) (*IPv4Header, error) {
	i := IPv4Header{}
	return &i, bytesToStruct(bytes, &i)
}

type IPv4Packet struct {
	Header *IPv4Header
	Data	 []byte
}

func NewBaseIPv4Header(dataLen uint16, protocol uint8, srcIP, dstIP [4]byte) *IPv4Header {
	return &IPv4Header {
		VersionAndIHL: 0x45, // IP header is version 4 and consists of 5 octet with no option.
		TypeOfService: 0x00, // all type is normal.
		TotalLength: dataLen + 20, // IP header length is 20 byte with no option.
		Identification: uint16(rand.Intn(16)),
		FlagsAndFragmentOffset: 1 << 14, // not consider fragment.
		TimeToLive: 64, // fix value for now
		Protocol: protocol,
		HeaderCheckSum: 0, // will be caliculated later.
		SourceAddress: srcIP,
		DestinationAddress: dstIP,
	}
}

func GetIPv4HeaderBytes(dataLen uint16, protocol uint8, srcIP, dstIP [4]byte) ([]byte, error) {
	h := NewBaseIPv4Header(dataLen, protocol, srcIP, dstIP)
	hBytes, err := h.Bytes()
	if err != nil {
		return nil, err
	}
	checkSum := getCheckSum(hBytes)
	bytes := append(hBytes[:10], checkSum...)
	bytes  = append(bytes, hBytes[12:]...)
	return bytes, nil
}
