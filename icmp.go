package tcpip

import (
	"sync"
	"errors"
	"context"
)

const (
	ICMP_TYPE_UNREACHABLE uint8 = 3
	ICMP_TYPE_TIME_EXCEEDED     = 11
	ICMP_TYPE_PARAMETER_PROBLEM = 12
	ICMP_TYPE_SOURCE_QUENCH     = 4
	ICMP_TYPE_REDIRECT          = 5
	ICMP_TYPE_ECHO_REQUEST      = 8
	ICMP_TYPE_ECHO_REPLY        = 0

	ICMP_ECHO_HEADER_SIZE int   = 8
)

// RFC792 https://tools.ietf.org/html/rfc792
type IcmpEchoHeader struct {
	Type           uint8
	Code           uint8
	HeaderChecksum uint16
	Identifier     uint16
	SequenceNumber uint16
}

func(i *IcmpEchoHeader) Bytes() ([]byte, error) {
	return structToBytes(i)
}

var (
	staticIcmpManagers *IcmpManagers = &IcmpManagers{m: map[string]*IcmpManager{}}
)

type IcmpManagers struct {
	sync.RWMutex
	m map[string]*IcmpManager
}

func (i *IcmpManagers) getManagerByNic(networkIfName string) (*IcmpManager, error) {
	i.RLock()
	manager, exist := i.m[networkIfName]
	i.RUnlock()
	if exist {
		return manager, nil
	}
	manager, err := newIcmpManager(networkIfName)
	if err != nil {
		return nil, err
	}
	go manager.readingIcmpLopp()
	i.Lock()
	i.m[networkIfName] = manager
	i.Unlock()
	return manager, nil
}


type IcmpManager struct {
	IPv4Socket
	l *IcmpEchoWaitingList
}

func newIcmpManager(nicName string) (*IcmpManager, error) {
	s, err := NewIPv4Socket(nicName, PROTOCOL_ICMP)
	if err != nil {
		return nil, err
	}
	return &IcmpManager {
		IPv4Socket: *s,
		l: &IcmpEchoWaitingList {
			m: make(map[uint16]*IcmpReplyWaiter),
		},
	}, nil
}

type IcmpEchoWaitingList struct {
	sync.RWMutex
	m map[uint16]*IcmpReplyWaiter
}

type IcmpReplyWaiter struct {
	replyHeader chan *IcmpEchoHeader
	err         chan error
}

func IcmpEcho(ctx context.Context, networkIfName string, ipAddr [4]byte, data []byte) (*IcmpEchoHeader, error) {
	replyHeaderChan, errChan := IcmpEchoAsync(networkIfName, ipAddr, data)
	select {
	case <-ctx.Done():
		return nil, errors.New("timeout")
	case err := <-errChan:
		return nil, err
	case replyHeader := <-replyHeaderChan:
		return replyHeader, nil
	}
}

func IcmpEchoAsync(networkIfName string, ipAddr [4]byte, data []byte) (chan *IcmpEchoHeader, chan error) {
	replyHeader := make(chan *IcmpEchoHeader, 1)
	err         := make(chan error, 1)
	manager, e := staticIcmpManagers.getManagerByNic(networkIfName)
	if e != nil {
		err <- e
		return nil, err
	}
	go manager.echoRequest(ipAddr, data, replyHeader, err)
	return replyHeader, err
}

func (i *IcmpManager) echoRequest(ipAddr [4]byte, data []byte, replyHeader chan *IcmpEchoHeader, err chan error) {
	var identifier uint16
	for {
		identifier = randomUint16()
		i.l.RLock()
		_, exist := i.l.m[identifier]
		i.l.RUnlock()
		if exist {
			continue
		}
		i.l.Lock()
		i.l.m[identifier] = &IcmpReplyWaiter {
			replyHeader: replyHeader,
			err: err,
		}
		i.l.Unlock()
		break
	}

	e := i.sendEchoRequest(ipAddr, identifier, data)
	if e != nil {
		i.l.Lock()
		delete(i.l.m, identifier)
		i.l.Unlock()
		err <- e
		return
	}
}

func (i *IcmpManager) sendEchoRequest(dstIpAddr [4]byte, identifier uint16, data []byte) error {
	h := IcmpEchoHeader {
		Type: 8,
		Code: 0,
		HeaderChecksum: 0,
		Identifier: identifier,
		SequenceNumber: 0,
	}
	hBytes, err := h.Bytes()
	if err != nil {
		return err
	}
	tempBytes := append(hBytes, data...)
	checkSum := getCheckSum(tempBytes)
	bytes := append(tempBytes[:2], checkSum...)
	bytes = append(bytes, tempBytes[4:]...)
	i.Write(dstIpAddr, bytes)
	if _, err = i.Write(dstIpAddr, bytes); err != nil {
		debugf("[icmp] failed to echo request. Error is '%v'", err)
	}
	return nil
}

func (i *IcmpManager) readingIcmpLopp() {
	for {
		packet, err := i.Read()
		if err != nil {
			debugf("[icmp] failed to read ICMP packet. %v", err)
			continue
		}
		hBytes := packet.Data[:ICMP_ECHO_HEADER_SIZE]
		header := IcmpEchoHeader{}
		if err = bytesToStruct(hBytes, &header); err != nil {
			debugf("[icmp] failed to read ICMP packet's header. header: '%v' err: '%v'", hBytes, err)
			continue
		}
		if header.Type == ICMP_TYPE_ECHO_REPLY {
			i.receivedReplyProcess(&header)
			continue
		}
		if header.Type == ICMP_TYPE_ECHO_REQUEST && *enableIcmpEchoResponse {
			i.receivedRequestProcess(&header, packet.Data[ICMP_ECHO_HEADER_SIZE:], packet.Header.SourceAddress)
			continue
		}
		debugf("[icmp] type %v is received but not supported now.", header.Type)
	}
}

func (i *IcmpManager) receivedReplyProcess(h *IcmpEchoHeader) {
	i.l.RLock()
	waiter, exist := i.l.m[h.Identifier]
	i.l.RUnlock()
	if !exist {
		debugf("[icmp] ICMP reply's identifier %X is not found in waiting reply list", h.Identifier)
		return
	}
	debugf("[icmp] ICMP reply's identifier %X is found in waiting reply list.", h.Identifier)
	waiter.replyHeader <- h
	i.l.Lock()
	defer i.l.Unlock()
	delete(i.l.m, h.Identifier)
}

func (i *IcmpManager) receivedRequestProcess(h *IcmpEchoHeader, data []byte, dstIpAddr [4]byte) {
	h.Type = ICMP_TYPE_ECHO_REPLY
	h.HeaderChecksum = 0
	hBytes, err := h.Bytes()
	if err != nil {
		return
	}
	tempBytes := append(hBytes, data...)
	checkSum := getCheckSum(tempBytes)
	bytes := append(tempBytes[:2], checkSum...)
	bytes = append(bytes, tempBytes[4:]...)
	if _, err = i.Write(dstIpAddr, bytes); err != nil {
		debugf("[icmp] failed to reply ICMP echo request. Error is '%v'", err)
	}
	debugf("[icmp] successful to reply ICMP echo request (id: %v)", h.Identifier)
	return
}
