package main

import (
	"fmt"
	"net"
)

func main() {
	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:2053")
	if err != nil {
		fmt.Println("Failed to resolve UDP address:", err)
		return
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		fmt.Println("Failed to bind to address:", err)
		return
	}
	defer udpConn.Close()

	buf := make([]byte, 512)

	for {
		size, source, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			fmt.Println("Error receiving data:", err)
			break
		}

		receivedData := string(buf[:size])
		fmt.Printf("Received %d bytes from %s: %s\n", size, source, receivedData)

		parsedDNSRequest, err := parseDNSMessage([]byte(receivedData))
		if err != nil {
			panic(err)
		}

		rcode := byte(4)
		if parsedDNSRequest.header.OPCODE == 0 {
			rcode = 0
		}

		dnsQuestion := []DNSQuestionSection{
			{
				Name:  parsedDNSRequest.questionSection[0].Name,
				Type:  1,
				Class: 1,
			},
		}

		dnsAnswer := []DNSAnswerSection{
			{
				Name:   parsedDNSRequest.questionSection[0].Name,
				Type:   1,
				Class:  1,
				TTL:    60,
				Length: 4,
				Data:   "8.8.8.8",
			},
		}

		response := NewDNSMessage(
			DNSHeader{
				ID:      parsedDNSRequest.header.ID,
				QR:      true,
				OPCODE:  parsedDNSRequest.header.OPCODE,
				AA:      false,
				TC:      false,
				RD:      parsedDNSRequest.header.RD,
				RA:      false,
				Z:       0,
				RCODE:   rcode,
				QDCOUNT: uint16(len(dnsQuestion)),
				ANCOUNT: uint16(len(dnsAnswer)),
				NSCOUNT: 0,
				ARCOUNT: 0,
			},
			dnsQuestion,
			dnsAnswer,
		)

		_, err = udpConn.WriteToUDP(response.ToBytes(), source)
		if err != nil {
			fmt.Println("Failed to send response:", err)
		}
	}
}
