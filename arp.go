package tcpip

import (
  "sync"
  "os"
  "strings"
  "strconv"
  "context"
  "errors"
)

const (
  ARP_OPE_REQUEST   uint16 = 0x0001
  ARP_OPE_REPLY     uint16 = 0x0002
  HTYPE_MAC_ADDRESS uint16 = 0x0001
)

// RFC826: https://tools.ietf.org/html/rfc826
type Arp struct {
  HardwareType       uint16
  ProtocolType       uint16
  HardwareLength     uint8
  ProtocolLength     uint8
  Operation          uint16
  SrcHardwareAddress [6]uint8
  SrcIPAddress       [4]uint8
  DstHardwareAddress [6]uint8
  DstIPAddress       [4]uint8
}

func NewArpRequest(srcMac [6]uint8, srcIP, dstIP [4]uint8) *Arp {
  return &Arp{
    HardwareType:       HTYPE_MAC_ADDRESS,
    ProtocolType:       PROTOCOL_IPV4,
    HardwareLength:     6,
    ProtocolLength:     4,
    Operation:          ARP_OPE_REQUEST,
    SrcHardwareAddress: srcMac,
    SrcIPAddress:       srcIP,
    DstHardwareAddress: [6]uint8{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    DstIPAddress:       dstIP,
  }
}

func NewArpReply(srcMac, dstMac [6]uint8, srcIP, dstIP [4]uint8) *Arp {
  return &Arp{
    HardwareType:       HTYPE_MAC_ADDRESS,
    ProtocolType:       PROTOCOL_IPV4,
    HardwareLength:     6,
    ProtocolLength:     4,
    Operation:          ARP_OPE_REPLY,
    SrcHardwareAddress: srcMac,
    SrcIPAddress:       srcIP,
    DstHardwareAddress: dstMac,
    DstIPAddress:       dstIP,
  }
}

func(a *Arp) Bytes() ([]byte, error) {
  return structToBytes(a)
}

var (
  staticArpTables *arpTables = &arpTables{tables: map[string]*arpTable{}}
)

type arpWaitQue struct {
  sync.RWMutex
  table map[[4]byte]chan [6]byte
}

func (a *arpWaitQue) getRecordSafely(macAddress [4]byte) (chan [6]byte, bool) {
  a.RLock()
  defer a.RUnlock()
  if record, exist := a.table[macAddress]; exist {
    return record, true
  }
  return nil, false
}

type arpTable struct {
  sync.RWMutex
  srcIPAddr [4]byte
  // key: IPv4, value: MAC address
  records map[[4]byte][6]byte
  socket  *EtherSocket
  que     *arpWaitQue
}

func (a *arpTable) getRecordSafely(macAddress [4]byte) ([6]byte, bool) {
  a.RLock()
  defer a.RUnlock()
  if record, exist := a.records[macAddress]; exist {
    return record, true
  }
  return [6]byte{}, false
}

func (a *arpTable) readingArpLoop() {
  debug("[arp] start loop to receive ARP packet.")
  for {
    packet, err := a.socket.Read()
    if err != nil {
      debug(err)
      continue
    }
    arp := Arp{}
    err = bytesToStruct(packet.Data, &arp)
    if err != nil {
      debug(err)
      continue
    }
    if !(arp.HardwareType == HTYPE_MAC_ADDRESS && arp.HardwareLength == 6 && arp.ProtocolLength == 4) {
      continue
    }
    if arp.Operation == ARP_OPE_REQUEST {
      if enableArpResponse == nil || !*enableArpResponse {
        continue
      }
      if arp.DstIPAddress != a.srcIPAddr {
        continue
      }
      res := NewArpReply(a.socket.macAddr, arp.SrcHardwareAddress, a.srcIPAddr, arp.SrcIPAddress)
      data, err := res.Bytes()
      if err != nil {
        continue
      }
      _, err = a.socket.Write(arp.SrcHardwareAddress, data)
      if err != nil {
        continue
      }
      continue
    }

    // notify to channel waiting ARP response.
    if c, queExists := a.que.getRecordSafely(arp.SrcIPAddress); queExists {
      debugf("[arp] found que item waiting for ARP response for %d.", arp.SrcIPAddress)
      // response que record of IP address that ARP table already have is deleted.
      if _, tableExists :=  a.getRecordSafely(arp.SrcIPAddress); tableExists {
        debugf("[arp] ARP record for %d is already registered and que will be deleted", arp.SrcIPAddress)
        a.que.Lock()
        delete(a.que.table, arp.SrcIPAddress)
        a.que.Unlock()
      } else {
        go func() {
          debugf("[arp] finish a que item for IP %d. MAC address is %d.", arp.SrcIPAddress, arp.SrcHardwareAddress)
          c <- arp.SrcHardwareAddress
        }()
      }
    }

    // insert new arp record.
    a.Lock()
    a.records[arp.SrcIPAddress] = arp.SrcHardwareAddress
    a.Unlock()
  }
}

// First, searching for record related to IP address from arp table. When not finding, request arp.
func (a *arpTable) findMacAddr(dstIPAddr [4]byte, dstMacAddr chan [6]byte, err chan error) {
  if v, exist := a.getRecordSafely(dstIPAddr); exist {
    dstMacAddr <-v
    return
  }

  arp := NewArpRequest(a.socket.macAddr, a.srcIPAddr, dstIPAddr)
  a.que.Lock()
  if _, exists := a.que.table[dstIPAddr]; !exists {
    a.que.table[dstIPAddr] = make(chan [6]byte, 1)
    debugf("[arp] added new item waiting ARP response to que for ip %d.", dstIPAddr)
  }
  a.que.Unlock()
  data, e := arp.Bytes()
  if e != nil {
    err <-e
    return
  }
  _, e = a.socket.Write([6]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, data)
  if e != nil {
    err <-e
    return
  }
  debugf("[arp] successful to send ARP request for ip %d. Waiting response.", dstIPAddr)
  tmp := <-a.que.table[dstIPAddr]
  dstMacAddr <- tmp
}

type arpTables struct {
  sync.RWMutex
  tables map[string]*arpTable
}

func (a *arpTables) getArpTableByIf(networkIfName string) (*arpTable, error) {
  table := func() *arpTable {
    // At same time, arpTables may be writed.
    a.RLock()
    defer a.RUnlock()
    if table, exist := a.tables[networkIfName]; exist {
      return table
    }
    debugf("[arp] ARP table for %s was not found and will be created.", networkIfName)
    return nil
  }()
  if table != nil {
    return table, nil
  }
  return a.newArpTableByIf(networkIfName)
}

func (a *arpTables) newArpTableByIf(networkIfName string) (*arpTable, error) {
  table := &arpTable {
    records: map[[4]byte][6]byte{},
    que    : &arpWaitQue { table: map[[4]byte]chan [6]byte{} },
  }
  var err error
  table.socket, err = GetEtherSocket(networkIfName, PROTOCOL_ARP)
  if err != nil {
    return nil, err
  }

  // set source IP address.
  if ipv4, exists := iPv4AddrByNIC[networkIfName]; exists {
    table.srcIPAddr = ipv4
    EnableArpResponse(true)
  } else {
    table.srcIPAddr, err = getNicIPAddress(networkIfName)
    if err != nil {
      return nil, err
    }
  }

  // set initial pairs of IP and MAC address
  if includeOsARPTable == nil || *includeOsARPTable {
    table.records, err = getLinuxArpRecords(networkIfName)
    if err != nil {
      return nil, err
    }
  }
  table.records[table.srcIPAddr] = table.socket.macAddr
  debug("[arp] initial ARP records:", table.records)

  a.Lock()
  defer a.Unlock()
  a.tables[networkIfName] = table
  go table.readingArpLoop()
  return table, nil
}

func getLinuxArpRecords(networkIfName string) (map[[4]byte][6]byte, error) {
  records := map[[4]byte][6]byte {}
  raw, err := os.ReadFile("/proc/net/arp")
  if err != nil {
    return nil, err
  }
  rs := strings.Split(string(raw), "\n")
  // first record is header and skipped.
  FindRecordLoop: for _, line := range rs[1:len(rs)] {
    columns := strings.Fields(line)
    if len(columns) < 6 {
      continue
    }
    if columns[5] != networkIfName {
      continue
    }

    strArrIP  := strings.Split(columns[0], ".")
    if len(strArrIP) != 4 {
      continue
    }
    var ip [4]byte
    for i, v := range strArrIP {
      p, err := strconv.Atoi(v)
      ip[i] = byte(p)
      if err != nil {
        continue FindRecordLoop
      }
    }

    strArrMac := strings.Split(columns[3], ":")
    if len(strArrMac) != 6 {
      continue
    }
    var mac [6]byte
    for i, v := range strArrMac {
      p, err := strconv.ParseInt(v, 16, 64)
      mac[i] = byte(p)
      if err != nil {
        continue FindRecordLoop
      }
    }

    records[ip] = mac
  }
  return records, nil
}

func ArppingAsync(networkIfName string, ipAddr [4]byte) (chan [6]byte, chan error) {
  macAddr := make(chan [6]byte, 1)
  err := make(chan error, 1)
  table, e := staticArpTables.getArpTableByIf(networkIfName)
  if e != nil {
    err <- e
    return nil, err
  }
  go table.findMacAddr(ipAddr, macAddr, err)
  return macAddr, err
}

func Arpping(ctx context.Context, networkIfName string, ipAddr [4]byte) ([6]byte, error) {
  macAddr, err := ArppingAsync(networkIfName, ipAddr)
  select {
  case <- ctx.Done():
    return [6]byte{}, errors.New("timeout")
  case a := <-macAddr:
    return a, nil
  case e := <-err:
    return [6]byte{}, e
  }
}
