package tcpip

var (
	enableDebugLog *bool
	iPv4AddrByNIC map[string][4]byte = map[string][4]byte{}
	includeOsARPTable *bool
	enableArpResponse *bool
	enableIcmpEchoResponse *bool
)

func EnableDebugLog(y bool) {
	enableDebugLog = &y
}

func SetIPv4ByNIC(infName string, ip [4]byte) {
	iPv4AddrByNIC[infName] = ip
}

func IncludeOsARPTable(y bool) {
	includeOsARPTable = &y
}

func EnableArpResponse(y bool) {
	enableArpResponse = &y
}

func EnableIcmpEchoResponse(y bool) {
	enableIcmpEchoResponse = &y
}
