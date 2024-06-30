package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
)

type DNSMessage struct {
	header          DNSHeader
	questionSection []DNSQuestionSection
	answerSection   []DNSAnswerSection
}

type DNSQuestionSection struct {
	Name  string
	Type  uint16
	Class uint16
}

type DNSAnswerSection struct {
	Name   string
	Type   uint16
	Class  uint16
	TTL    uint32
	Length uint16
	Data   string
}

func (m *DNSMessage) ToBytes() []byte {
	buf := bytes.Buffer{}
	binary.Write(&buf, binary.BigEndian, m.header.ToBytes())
	binary.Write(&buf, binary.BigEndian, m.questionSection[0].ToBytes())
	binary.Write(&buf, binary.BigEndian, m.answerSection[0].ToBytes())

	return buf.Bytes()
}

func NewDNSMessage(h DNSHeader, q []DNSQuestionSection, a []DNSAnswerSection) DNSMessage {
	return DNSMessage{
		header:          h,
		questionSection: q,
		answerSection:   a,
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

func (a *DNSAnswerSection) ToBytes() []byte {
	buf := bytes.Buffer{}

	binary.Write(&buf, binary.BigEndian, encodeDomainToBytes(a.Name))
	binary.Write(&buf, binary.BigEndian, a.Type)
	binary.Write(&buf, binary.BigEndian, a.Class)
	binary.Write(&buf, binary.BigEndian, a.TTL)
	binary.Write(&buf, binary.BigEndian, a.Length)
	binary.Write(&buf, binary.BigEndian, encodeIPToBytes(a.Data))

	return buf.Bytes()
}

func encodeIPToBytes(ip string) []byte {
	encodedIP := bytes.Buffer{}

	for _, seg := range strings.Split(ip, ".") {
		n := len(seg)
		binary.Write(&encodedIP, binary.BigEndian, byte(n))
		binary.Write(&encodedIP, binary.BigEndian, []byte(seg))
	}

	return encodedIP.Bytes()
}

func parseDNSMessage(data []byte) (DNSMessage, error) {
	reader := bytes.NewReader(data)

	dnsHeader, err := parseDNSHeader(data)
	if err != nil {
		return DNSMessage{}, err
	}

	reader.Seek(12, io.SeekStart)
	dnsQuestionSection, err := parseDNSQuestionSection(reader, dnsHeader.QDCOUNT)
	if err != nil {
		return DNSMessage{}, err
	}

	dnsAnswerSection, err := parseDNSAnswerSection(reader, dnsHeader.ANCOUNT)
	if err != nil {
		return DNSMessage{}, err
	}

	return NewDNSMessage(
		dnsHeader,
		dnsQuestionSection,
		dnsAnswerSection,
	), nil
}

func parseDNSHeader(data []byte) (DNSHeader, error) {
	// DNS header should atleast be 12 bytes
	if len(data) < 12 {
		return DNSHeader{}, fmt.Errorf("DNS Header less than 12 bytes")
	}

	dnsHeader := DNSHeader{
		ID: binary.BigEndian.Uint16(data[0:2]),
	}

	thirdAndFourthByte := binary.BigEndian.Uint16(data[2:4])

	dnsHeader.QR = (thirdAndFourthByte >> 15 & 0x01) > 0
	dnsHeader.OPCODE = uint8(thirdAndFourthByte >> 11 & 0x0F)
	dnsHeader.AA = (thirdAndFourthByte >> 10 & 0x01) > 0
	dnsHeader.TC = (thirdAndFourthByte >> 9 & 0x01) > 0
	dnsHeader.RD = (thirdAndFourthByte >> 8 & 0x01) > 0

	dnsHeader.RA = (thirdAndFourthByte >> 7 & 0x01) > 0
	dnsHeader.Z = uint8(thirdAndFourthByte >> 4 & 0x07)
	dnsHeader.RCODE = uint8(thirdAndFourthByte & 0x0F)

	dnsHeader.QDCOUNT = binary.BigEndian.Uint16(data[4:6])
	dnsHeader.ANCOUNT = binary.BigEndian.Uint16(data[6:8])
	dnsHeader.NSCOUNT = binary.BigEndian.Uint16(data[8:10])
	dnsHeader.ARCOUNT = binary.BigEndian.Uint16(data[10:])

	return dnsHeader, nil
}

func parseDNSQuestionSection(reader *bytes.Reader, qdCount uint16) ([]DNSQuestionSection, error) {
	dnsQuestions := []DNSQuestionSection{}

	for i := 0; i < int(qdCount); i++ {
		name, err := parsedName(reader)
		if err != nil {
			return []DNSQuestionSection{}, fmt.Errorf("failed to parse question name")
		}

		q := DNSQuestionSection{
			Name: name,
		}

		err = binary.Read(reader, binary.BigEndian, &q.Type)
		if err != nil {
			return []DNSQuestionSection{}, fmt.Errorf("failed to read question type")
		}

		err = binary.Read(reader, binary.BigEndian, &q.Class)
		if err != nil {
			return []DNSQuestionSection{}, fmt.Errorf("failed to read question class")
		}

		dnsQuestions = append(dnsQuestions, q)
	}

	return dnsQuestions, nil
}

func parseDNSAnswerSection(reader *bytes.Reader, anCount uint16) ([]DNSAnswerSection, error) {
	dnsAnswerSection := []DNSAnswerSection{}

	for i := 0; i < int(anCount); i++ {
		name, err := parsedName(reader)
		if err != nil {
			return []DNSAnswerSection{}, fmt.Errorf("failed to parse answer name")
		}

		a := DNSAnswerSection{
			Name: name,
		}

		err = binary.Read(reader, binary.BigEndian, &a.Type)
		if err != nil {
			return []DNSAnswerSection{}, fmt.Errorf("failed to parse answer type")
		}

		err = binary.Read(reader, binary.BigEndian, &a.Class)
		if err != nil {
			return []DNSAnswerSection{}, fmt.Errorf("failed to parse answer class")
		}

		err = binary.Read(reader, binary.BigEndian, &a.TTL)
		if err != nil {
			return []DNSAnswerSection{}, fmt.Errorf("failed to parse answer ttl")
		}

		err = binary.Read(reader, binary.BigEndian, &a.Length)
		if err != nil {
			return []DNSAnswerSection{}, fmt.Errorf("failed to parse answer length")
		}

		err = binary.Read(reader, binary.BigEndian, &a.Data)
		if err != nil {
			return []DNSAnswerSection{}, fmt.Errorf("failed to parse answer data")
		}

		dnsAnswerSection = append(dnsAnswerSection, a)
	}

	return dnsAnswerSection, nil
}

func parsedName(reader *bytes.Reader) (string, error) {
	var parsedName string
	var length byte
	for {
		err := binary.Read(reader, binary.BigEndian, &length)
		if err != nil {
			return "", fmt.Errorf("failed to parse name")
		}

		if length == 0 {
			break
		}

		label := make([]byte, length)
		_, err = reader.Read(label)
		if err != nil {
			return "", fmt.Errorf("failed to read labels")
		}

		if len(parsedName) > 0 {
			parsedName += "."
		}

		parsedName += string(label)
	}

	return parsedName, nil
}
