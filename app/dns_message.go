package main

import (
	"bytes"
	"encoding/binary"
	"strings"
)

type DNSMessage struct {
	header          DNSHeader
	questionSection DNSQuestionSection
}

func (m *DNSMessage) ToBytes() []byte {
	buf := bytes.Buffer{}
	binary.Write(&buf, binary.BigEndian, m.header.ToBytes())
	binary.Write(&buf, binary.BigEndian, m.questionSection.ToBytes())

	return buf.Bytes()
}

func NewDNSMessage(h DNSHeader, q DNSQuestionSection) DNSMessage {
	return DNSMessage{
		header:          h,
		questionSection: q,
	}
}

type DNSHeader struct {
	ID      uint16 // 16 bits
	QR      bool   // 1 bit
	OPCODE  byte   // 4 bits
	AA      bool   // 1 bit
	TC      bool   // 1 bit
	RD      bool   // 1 bit
	RA      bool   // 1 bit
	Z       byte   // 3 bits
	RCODE   byte   // 4 bits
	QDCOUNT uint16 // 16 bits
	ANCOUNT uint16 // 16 bits
	NSCOUNT uint16 // 16 bits
	ARCOUNT uint16 // 16 bits
}

func (h *DNSHeader) ToBytes() []byte {
	buf := bytes.Buffer{}
	binary.Write(&buf, binary.BigEndian, h.ID) // 2 bytes

	thirdByte := getThirdByte(h)
	fourthByte := getFourthByte(h)

	binary.Write(&buf, binary.BigEndian, thirdByte)
	binary.Write(&buf, binary.BigEndian, fourthByte)
	binary.Write(&buf, binary.BigEndian, h.QDCOUNT)
	binary.Write(&buf, binary.BigEndian, h.ANCOUNT)
	binary.Write(&buf, binary.BigEndian, h.NSCOUNT)
	binary.Write(&buf, binary.BigEndian, h.ARCOUNT)

	return buf.Bytes()
}

func getThirdByte(h *DNSHeader) uint8 {
	thirdByte := uint8(0)

	if h.QR {
		thirdByte = thirdByte | (1 << 7)
	}

	thirdByte = thirdByte | (h.OPCODE << 3)

	if h.AA {
		thirdByte = thirdByte | (1 << 2)
	}
	if h.TC {
		thirdByte = thirdByte | (1 << 1)
	}
	if h.RD {
		thirdByte = thirdByte | 1
	}

	return thirdByte
}

func getFourthByte(h *DNSHeader) uint8 {
	fourthByte := uint8(0)

	if h.RA {
		fourthByte = fourthByte | (1 << 7)
	}
	fourthByte = fourthByte | (h.Z << 4)
	fourthByte = fourthByte | (h.RCODE)

	return fourthByte
}

type DNSQuestionSection struct {
	Name  string
	Type  uint16
	Class uint16
}

func (q *DNSQuestionSection) ToBytes() []byte {
	buf := bytes.Buffer{}

	binary.Write(&buf, binary.BigEndian, encodeDomainToBytes(q.Name))
	binary.Write(&buf, binary.BigEndian, q.Type)
	binary.Write(&buf, binary.BigEndian, q.Class)

	return buf.Bytes()
}

func encodeDomainToBytes(domain string) []byte {
	encodedDomain := bytes.Buffer{}

	for _, seg := range strings.Split(domain, ".") {
		n := len(seg)
		binary.Write(&encodedDomain, binary.BigEndian, byte(n))
		binary.Write(&encodedDomain, binary.BigEndian, []byte(seg))
	}

	return append(encodedDomain.Bytes(), 0x00)
}
