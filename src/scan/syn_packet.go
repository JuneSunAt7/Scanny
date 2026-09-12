package scan

import (
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func SendSYNPacket(srcIP, dstIP string, srcPort, dstPort int) error {
	srcIPNet := net.ParseIP(srcIP)
	dstIPNet := net.ParseIP(dstIP)

	// 2. create layer IPv4
	ipLayer := &layers.IPv4{
		SrcIP:    srcIPNet,
		DstIP:    dstIPNet,
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}

	// 3. create layer TCP flag SYN
	tcpLayer := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		Seq:     110502, // random number
		SYN:     true,
		Window:  14600,
	}
	if err := tcpLayer.SetNetworkLayerForChecksum(ipLayer); err != nil {
		return err
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	err := gopacket.SerializeLayers(buf, opts, ipLayer, tcpLayer)
	if err != nil {
		return err
	}
	conn, err := net.Dial("ip4:tcp", dstIP)
	if err != nil {
		return err
	}
	defer conn.Close()

	_, err = conn.Write(buf.Bytes())
	return err
}