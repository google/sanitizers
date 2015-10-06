package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
)

const (
	magic32SecondHalf uint32 = 0xFFFFFF32
	magic64SecondHalf uint32 = 0xFFFFFF64
	magicFirstHalf    uint32 = 0xC0BFFFFF
)

func usage() {
	progName := os.Args[0]
	fmt.Printf("Usage:\n")
	fmt.Printf(" %s print FILE [FILE...]\n", progName)
	os.Exit(-1)
}

func readMagicAndReturnBitness(r io.Reader) (uint8, error) {
	header := []uint32{0, 0}
	if err := binary.Read(r, binary.LittleEndian, header); err != nil {
		return 0, err
	}

	if header[1] != magicFirstHalf {
		return 0, fmt.Errorf("wrong magic: %x", header)
	}

	switch header[0] {
	default:
		return 0, fmt.Errorf("wrong bits: %x", header)
	case magic32SecondHalf:
		return 32, nil
	case magic64SecondHalf:
		return 64, nil
	}
}

func readOneFile(path string) ([]uint64, error) {
	content, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	reader := bytes.NewReader(content)
	bits, err := readMagicAndReturnBitness(reader)
	if err != nil {
		return nil, fmt.Errorf("File %s has corrupted header: %s", path, err)
	}

	size := len(content)
	switch bits {
	default:
		return nil, fmt.Errorf("File %s has unsupported bits size: %d", path, bits)
	case 32:
		data := make([]uint32, (size-8)/4)
		if err := binary.Read(reader, binary.LittleEndian, data); err != nil {
			return nil, err
		}
		data64 := make([]uint64, len(data))
		for i, w := range data64 {
			data64[i] = uint64(w)
		}
		return data64, nil
	case 64:
		data := make([]uint64, (size-8)/8)
		if err := binary.Read(reader, binary.LittleEndian, data); err != nil {
			return nil, err
		}
		return data, nil
	}
}

func print(files []string) error {
	if len(files) == 0 {
		fmt.Printf("At least one file should be specified\n")
		usage()
	}

	if len(files) > 1 {
		return fmt.Errorf("File merge is not implemented yet")
	}

	data, err := readOneFile(files[0])
	if err != nil {
		return err
	}

	for _, addr := range data {
		fmt.Printf("0x%x\n", addr)
	}

	return nil
}

func main() {
	flag.Parse()
	args := flag.Args()

	if len(args) == 0 {
		usage()
		return
	}

	var err error
	switch cmd := args[0]; cmd {
	case "print":
		err = print(args[1:])
	default:
		fmt.Printf("Unsupported command: %s\n", cmd)
		usage()
	}

	if err != nil {
		fmt.Printf("Error: %q", err)
	}
}
