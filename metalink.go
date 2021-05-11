package main

import (
	"bufio"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
)

type Hash struct {
	XMLName xml.Name `xml:"hash"`
	Type    string   `xml:"type,attr,omitempty"`
	Value   string   `xml:",chardata"`
}

type Pieces struct {
	XMLName xml.Name `xml:"pieces"`
	Length  int      `xml:"length,attr"`
	Type    string   `xml:"type,attr"`
	Hashes  []Hash
}

type Metalink struct {
	XMLName xml.Name `xml:"file"`
	Name    string   `xml:"name,attr"`
	Size    int64    `xml:"size"`
	Hashes  []Hash
	Pieces  Pieces
}

func calcFileHashes(fileName string, blockSize int) *Metalink {
	f, err := os.Open(fileName)
	if err != nil {
		log.Fatalf("Error to read [file=%v]: %v", fileName, err.Error())
	}

	nBytes := int64(0)
	r := bufio.NewReader(f)
	buf := make([]byte, 0, blockSize)
	finito := false
	res := Metalink{Name: fileName}
	var pieces []Hash
	_md5 := md5.New()
	_sha1 := sha1.New()
	_sha256 := sha256.New()
	for {
		n, err := r.Read(buf[:cap(buf)])
		buf = buf[:n]
		if n == 0 {
			if err == nil {
				continue
			}
			if err == io.EOF {
				break
			}
			log.Fatal(err)
		}
		if finito {
			log.Fatal("Finito?") // shouldn't happen?
		}
		if n < blockSize {
			finito = true
		}
		nBytes += int64(len(buf))
		if err != nil && err != io.EOF {
			log.Fatal(err)
		}
		_md5.Write(buf)
		_sha1.Write(buf)
		_sha256.Write(buf)
                piece := sha1.Sum(buf)
                pieces = append(pieces, Hash{Value: hex.EncodeToString(piece[:])})
	}
	res.Size = nBytes
	res.Hashes = []Hash{
		Hash{Type: "md5",     Value: hex.EncodeToString(_md5.Sum(nil))},
		Hash{Type: "sha-1",   Value: hex.EncodeToString(_sha1.Sum(nil))},
		Hash{Type: "sha-256", Value: hex.EncodeToString(_sha256.Sum(nil))},
	}
	res.Pieces = Pieces{Length: blockSize, Type: "sha-1", Hashes: pieces}
	return &res
}

func printXml(m *Metalink) {
	output, err := xml.MarshalIndent(m, "  ", "    ")
	if err != nil {
		log.Fatal("error: %v\n", err)
	}
	os.Stdout.Write(output)
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Missing parameter, provide file name!")
		return
	}
	blockSize := 256 * 1024
	if len(os.Args) > 2 {
		var err error
		if blockSize, err = strconv.Atoi(os.Args[2]); err != nil {
			log.Fatal(err)
		}
	}
	fileName := os.Args[1]
	res := calcFileHashes(fileName, blockSize)
        printXml(res)
}
