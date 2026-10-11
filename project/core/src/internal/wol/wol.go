package wol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"syscall"
	"time"
)

const (
	Phase        = "wol"
	wolEtherType = uint16(0x0842)
)

// SendResult mirrors the proven r6 dual-path behavior: raw Ethernet Magic
// Packets are sent on the selected interface and bridge members, while UDP
// broadcast is sent on the selected interface. Partial success is success.
type SendResult struct {
	RawSent    int      `json:"raw_sent"`
	UDPSent    int      `json:"udp_sent"`
	Interfaces []string `json:"interfaces"`
	Warnings   []string `json:"warnings,omitempty"`
}

type Transport interface {
	Send(ifname string, members []string, mac string) (SendResult, error)
}

type Sender struct{}

func packet(mac net.HardwareAddr) []byte {
	p := make([]byte, 6+16*len(mac))
	for i := 0; i < 6; i++ {
		p[i] = 0xff
	}
	for i := 0; i < 16; i++ {
		copy(p[6+i*len(mac):], mac)
	}
	return p
}

func ethernetFrame(src, dst net.HardwareAddr) ([]byte, error) {
	if len(src) != 6 {
		return nil, errors.New("send interface has no valid ethernet MAC")
	}
	if len(dst) != 6 {
		return nil, errors.New("invalid target MAC")
	}
	payload := packet(dst)
	frame := make([]byte, 14+len(payload))
	for i := 0; i < 6; i++ {
		frame[i] = 0xff
	}
	copy(frame[6:12], src)
	binary.BigEndian.PutUint16(frame[12:14], wolEtherType)
	copy(frame[14:], payload)
	return frame, nil
}

func htons(v uint16) uint16 { return (v << 8) | (v >> 8) }

func uniqueInterfaces(ifname string, members []string) []string {
	ifname = strings.TrimSpace(ifname)
	seen := map[string]bool{}
	out := make([]string, 0, 1+len(members))
	add := func(name string) {
		name = strings.TrimSpace(name)
		if name == "" || seen[name] {
			return
		}
		seen[name] = true
		out = append(out, name)
	}
	add(ifname)
	sorted := append([]string(nil), members...)
	sort.Strings(sorted)
	for _, m := range sorted {
		add(m)
	}
	return out
}

func sendRaw(ifname string, mac net.HardwareAddr) (int, error) {
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		return 0, err
	}
	frame, err := ethernetFrame(iface.HardwareAddr, mac)
	if err != nil {
		return 0, err
	}
	proto := htons(wolEtherType)
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(proto))
	if err != nil {
		return 0, err
	}
	defer syscall.Close(fd)

	sa := &syscall.SockaddrLinklayer{Protocol: proto, Ifindex: iface.Index, Halen: 6}
	for i := 0; i < 6; i++ {
		sa.Addr[i] = 0xff
	}
	count := 0
	for n := 0; n < 3; n++ {
		if err := syscall.Sendto(fd, frame, 0, sa); err != nil {
			return count, err
		}
		count++
		time.Sleep(40 * time.Millisecond)
	}
	return count, nil
}

func interfaceBroadcast(ifname string) net.IP {
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		return net.IPv4bcast
	}
	addrs, _ := iface.Addrs()
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok || ipnet.IP.To4() == nil {
			continue
		}
		ip := ipnet.IP.To4()
		mask := ipnet.Mask
		if len(mask) != 4 {
			continue
		}
		b := make(net.IP, 4)
		for i := 0; i < 4; i++ {
			b[i] = ip[i] | ^mask[i]
		}
		return b
	}
	return net.IPv4bcast
}

func sendUDP(ifname string, mac net.HardwareAddr) (int, error) {
	c, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return 0, err
	}
	defer c.Close()
	raw, err := c.SyscallConn()
	if err != nil {
		return 0, err
	}
	var optErr error
	if err := raw.Control(func(fd uintptr) {
		if e := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1); e != nil && optErr == nil {
			optErr = e
		}
		if e := syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, ifname); e != nil && optErr == nil {
			optErr = e
		}
	}); err != nil {
		return 0, err
	}
	if optErr != nil {
		return 0, optErr
	}

	pkt := packet(mac)
	dsts := []net.IP{interfaceBroadcast(ifname), net.IPv4bcast}
	count := 0
	for n := 0; n < 3; n++ {
		for _, ip := range dsts {
			if _, err := c.WriteToUDP(pkt, &net.UDPAddr{IP: ip, Port: 9}); err != nil {
				return count, err
			}
			count++
		}
		time.Sleep(80 * time.Millisecond)
	}
	return count, nil
}

func (Sender) Send(ifname string, members []string, macText string) (SendResult, error) {
	result := SendResult{Interfaces: []string{}}
	ifname = strings.TrimSpace(ifname)
	if ifname == "" {
		ifname = "br-lan"
	}
	mac, err := net.ParseMAC(strings.TrimSpace(macText))
	if err != nil || len(mac) != 6 {
		return result, errors.New("invalid MAC address")
	}
	if _, err := net.InterfaceByName(ifname); err != nil {
		return result, fmt.Errorf("network interface %s does not exist", ifname)
	}

	var warnings []string
	for _, rawIf := range uniqueInterfaces(ifname, members) {
		n, sendErr := sendRaw(rawIf, mac)
		result.RawSent += n
		if n > 0 {
			result.Interfaces = append(result.Interfaces, rawIf)
		}
		if sendErr != nil {
			warnings = append(warnings, fmt.Sprintf("raw/%s: %v", rawIf, sendErr))
		}
	}

	n, udpErr := sendUDP(ifname, mac)
	result.UDPSent = n
	if udpErr != nil {
		warnings = append(warnings, fmt.Sprintf("udp/%s: %v", ifname, udpErr))
	}
	if len(warnings) > 0 {
		result.Warnings = warnings
	}
	if result.RawSent == 0 && result.UDPSent == 0 {
		return result, fmt.Errorf("WOL send failed: %s", strings.Join(warnings, "; "))
	}
	return result, nil
}
