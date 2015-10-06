package main

import (
	"reflect"
	"testing"
)

func TestTimeConsuming(t *testing.T) {
	addrs, err := readOneFile("data1_64.sancov")

	expectedLen := 5159
	expectedAddrs := []uint64{0x4ee6b4, 0x4ee72c, 0x4ee760, 0x4ee7a1, 0x4ee806, 0x4ee90c, 0x4ee96a, 0x4ee9ec, 0x4eea9b, 0x4eeaf9}

	if err != nil {
		t.Error(err)
	}

	if len(addrs) != expectedLen {
		t.Errorf("Expected length: %d, but actual: %d", expectedLen, len(addrs))
	}

	actualAddrs := addrs[:len(expectedAddrs)]
	if !reflect.DeepEqual(expectedAddrs, actualAddrs) {
		t.Errorf("Expected: %v, but actual: %v", expectedAddrs, actualAddrs)
	}
}
