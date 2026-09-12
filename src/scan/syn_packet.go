package scan


import (
	"net"
	"://github.com"
	"://github.com/layers"
)

// sendSYNPacket собирает и отправляет один TCP SYN пакет
func SendSYNPacket(srcIP, dstIP string, srcPort, dstPort int) error {
	// 1. Преобразуем IP-адреса в формат net.IP
	srcIPNet := net.ParseIP(srcIP)
	dstIPNet := net.ParseIP(dstIP)

	// 2. Создаем слой IPv4
	ipLayer := &layers.IPv4{
		SrcIP:    srcIPNet,
		DstIP:    dstIPNet,
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}

	// 3. Создаем слой TCP с флагом SYN
	tcpLayer := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		Seq:     110502, // Произвольное стартовое число (Sequence Number)
		SYN:     true,   // Включаем флаг SYN
		Window:  14600,  // Размер окна передачи
	}

	// Критически важно: настраиваем расчет контрольной суммы TCP.
	// TCP требует "псевдо-заголовок" IP для валидации чексумы.
	if err := tcpLayer.SetNetworkLayerForChecksum(ipLayer); err != nil {
		return err
	}

	// 4. Буферизируем и сериализуем пакет в байты
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true, // Авторасчет контрольных сумм IP и TCP
		FixLengths:       true,
	}

	// Собираем слои вместе
	err := gopacket.SerializeLayers(buf, opts, ipLayer, tcpLayer)
	if err != nil {
		return err
	}

	// 5. Открываем сырой сокет (Raw Socket) для отправки IPv4/TCP
	// "ip4:tcp" означает, что ОС сама добавит Ethernet-заголовок, 
	// но уровни IP и TCP мы контролируем полностью.
	conn, err := net.Dial("ip4:tcp", dstIP)
	if err != nil {
		return err
	}
	defer conn.Close()

	// 6. Отправляем байты в сеть
	_, err = conn.Write(buf.Bytes())
	return err
}
