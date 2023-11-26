package tcpip

import (
	"os"
	"strings"
	"encoding/hex"
	"encoding/binary"
	"errors"
	"bytes"
	"net"
	"math/rand"
	"time"
	"sync"
)

func htons(i uint16) uint16 {
	return (i<<8)&0xff00 | i>>8
}

func structToBytes(structs ...interface{}) ([]byte, error) {
	buf := new(bytes.Buffer)
	for _, s := range structs {
		if err := binary.Write(buf, binary.BigEndian, s); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

func bytesToStruct(data []byte, s interface{}) error {
	r := bytes.NewReader(data)
	return binary.Read(r, binary.BigEndian, s)
}

func getNicIPAddress(networkIfName string) ([4]byte, error) {
	inf, err := net.InterfaceByName(networkIfName)
	if err != nil {
		return [4]byte{}, err
	}
	netInterfaceAddresses, err := inf.Addrs()
	if err != nil {
		return [4]byte{}, err
	}
	for _, netInterfaceAddress := range netInterfaceAddresses {
		networkIp, ok := netInterfaceAddress.(*net.IPNet)
		if !ok {
			continue
		}
		ipv4 := networkIp.IP.To4()
		if ipv4 == nil {
			continue
		}
		var result [4]byte
		for i, p := range ipv4 {
			result[i] = p
		}
		return result, nil
	}
	return [4]byte{}, errors.New("Not found IP for " + networkIfName)
}

func getDefaultGateway(networkIfName string) ([4]byte, error) {
	raw, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return [4]byte{}, err
	}
	lines := strings.Split(string(raw), "\n")
	for _, line := range lines {
		// 0: NIC name, 1: destination IP, 2: gateway IP
		parts := strings.Fields(line)
		if len(parts) < 2 || !(parts[0] == networkIfName && parts[1] == "00000000") {
			continue
		}
		rawDisplayedIP := parts[2]
		ip, err := hex.DecodeString(rawDisplayedIP)
		if err != nil {
			return [4]byte{}, err
		}
		for i, j := 0, len(ip)-1; i < j; i, j = i+1, j-1 {
			ip[i], ip[j] = ip[j], ip[i]
		}
		return *(*[4]byte)(ip[:4]), nil
	}
	return [4]byte{}, errors.New("default gateway is not found.")
}

func getCheckSum(data []byte) []byte {
	if len(data) %2 != 0 {
		data = append(data, 0)
	}

	var sum uint32
	for i := 0; i < len(data); i+=2 {
		for j := 0; j < 2; j++ {
			sum += uint32(data[i+j]) << ((1-j)*8)
		}
	}

	var checksum uint16 = 0xffff - uint16(sum) - uint16(sum >> 16)
	bytes := make([]byte, 2)
	binary.BigEndian.PutUint16(bytes, checksum)
	return bytes
}

func randomUint16() uint16 {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	return uint16(r.Int())
}

type ephemeralPorts struct {
	sync.RWMutex
	m map[uint16]bool
}

var staticEphemeralPorts ephemeralPorts = ephemeralPorts{m: map[uint16]bool{}}

func getNewEphemeralPort() (uint16, error) {
	staticEphemeralPorts.Lock()
	defer staticEphemeralPorts.Unlock()
	// using 61000 - 62000 as ephemeral port for now, beacuse almost Linux uses up to 60999 by default.
	for i := uint16(61000); i < 62001; i++ {
		if staticEphemeralPorts.m[i] {
			continue
		}
		staticEphemeralPorts.m[i] = true
		return i, nil
	}
	return 0, errors.New("All ephemeral ports are being used.")
}
