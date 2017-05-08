package ips

import (
	"testing"
	"bytes"
	"bufio"
)

var knownIps = [...]byte{
	0x50, 0x41, 0x54, 0x43, 0x48,
	0x00, 0x00, 0x15, 0x00, 0x00, 0x00, 0x0E, 0x07,
	0x00, 0x00, 0xFE, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04,
	0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0xFE,
	0x45, 0x4F, 0x46,
}

// TestRecreate tries to recreate a known-good ips patch
func TestRecreate(t *testing.T) {
	rdr := bytes.NewReader(knownIps[:])
	brdr := bufio.NewReader(rdr)
	pchan, echan := ReadIps(brdr)

	var wtr bytes.Buffer
	err := WriteIpsChan(&wtr,pchan)
	if !bytes.Equal(wtr.Bytes(), knownIps[:]) {
		t.Fatal("Could not recreate IPS!")
	}

	err = <-echan
	if err != nil {
		t.Fatalf("Error parsing known IPS: %v!", err)
	}
}

// TestApply applies a known patch and checks the results.
func TestApply(t *testing.T) {

}
