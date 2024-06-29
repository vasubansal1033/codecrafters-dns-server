package main

import (
	"encoding/binary"
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

		// Create an empty response
		id := binary.ByteOrder.Uint16(binary.BigEndian, buf[0:2])
		opCode := (buf[2] & 0b01111000) >> 3
		rd := (buf[2] & 0b00000001) == 1

		rcode := byte(4)
		if opCode == 0 {
			rcode = 0
		}

		response := NewDNSMessage(
			DNSHeader{
				ID:      id,
				QR:      true,
				OPCODE:  opCode,
				AA:      false,
				TC:      false,
				RD:      rd,
				RA:      false,
				Z:       0,
				RCODE:   rcode,
				QDCOUNT: 1,
				ANCOUNT: 1,
				NSCOUNT: 0,
				ARCOUNT: 0,
			},
			DNSQuestionSection{
				Name:  "codecrafters.io",
				Type:  1,
				Class: 1,
			},
			DNSAnswerSection{
				Name:   "codecrafters.io",
				Type:   1,
				Class:  1,
				TTL:    60,
				Length: 4,
				Data:   "8.8.8.8",
			},
		)

		_, err = udpConn.WriteToUDP(response.ToBytes(), source)
		if err != nil {
			fmt.Println("Failed to send response:", err)
		}
	}
}
