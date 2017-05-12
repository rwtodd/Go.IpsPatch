// Package ips contains types and functions to facilitate
// parsing and producing IPS patch files.
package ips

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/rwtodd/Go.AppUtil/errs"
)

const (
	eof_bytes = ('E' << 16) + ('O' << 8) + 'F'
)

type Patch interface {
	fmt.Stringer
	// ApplyTo applies the patch to the given WriterAt
	ApplyTo(io.WriterAt) error
	// writeIps formats the patch as an IPS fragment
	writeIps(io.Writer) error
}

// A bytepatch is a collections of values to be written to
// a locaition.
type bytepatch struct {
	values   []byte
	location uint32
}

func (bp *bytepatch) ApplyTo(ws io.WriterAt) error {
	if _, err := ws.WriteAt(bp.values, int64(bp.location)); err != nil {
		return errs.Wrap("Applying IPS patch", err)
	}
	return nil
}

func (bp *bytepatch) writeIps(w io.Writer) error {
	var err error
	var front [6]byte
	binary.BigEndian.PutUint32(front[:], uint32(bp.location))
	binary.BigEndian.PutUint16(front[4:], uint16(len(bp.values)))
	if _, err = w.Write(front[1:]); err != nil {
		return err
	}
	_, err = w.Write(bp.values)
	return err
}

func (bp *bytepatch) String() string {
	return fmt.Sprintf("%06X: Patch of length %d", bp.location, len(bp.values))
}

// An rlepatch is a patch consisting of a run of a single
// value.
type rlepatch struct {
	location uint32
	length   uint16
	value    byte
}

func (rp *rlepatch) ApplyTo(ws io.WriterAt) error {
	buf := bytes.Repeat([]byte{rp.value}, int(rp.length))
	if _, err := ws.WriteAt(buf, int64(rp.location)); err != nil {
		return errs.Wrap("Applying IPS patch", err)
	}
	return nil
}

func (rp *rlepatch) writeIps(w io.Writer) error {
	var err error
	var front [9]byte
	binary.BigEndian.PutUint32(front[:], uint32(rp.location))
	binary.BigEndian.PutUint16(front[6:], uint16(rp.length))
	front[8] = rp.value
	_, err = w.Write(front[1:])
	return err
}

func (rp *rlepatch) String() string {
	return fmt.Sprintf("%06X: RLE Patch of length %d, value %02X", rp.location, rp.length, rp.value)
}

// NewBytePatch creates a new patch from a series of bytes.
func NewBytePatch(loc uint32, vals []byte) Patch {
	return &bytepatch{values: vals, location: loc}
}

// NewRlePatch creates a new patch from a byte and a run-length.
func NewRlePatch(loc uint32, l uint16, val byte) Patch {
	return &rlepatch{location: loc, length: l, value: val}
}

// parseFile reads an entire patch file, pushing patches into a channel.
func parseFile(ips io.Reader, out chan Patch, echan chan error) {
	var (
		err  error
		buff [4]byte
	)

	read1 := func() byte {
		if err == nil {
			_, err = ips.Read(buff[:1])
		}
		return buff[0]
	}

	read2 := func() uint16 {
		if err == nil {
			_, err = io.ReadFull(ips, buff[:2])
		}
		return binary.BigEndian.Uint16(buff[:2])
	}

	read3 := func() uint32 {
		if err == nil {
			buff[0] = 0
			_, err = io.ReadFull(ips, buff[1:])
		}
		return binary.BigEndian.Uint32(buff[:])
	}

	defer close(out)
	defer close(echan)

	header := make([]byte, 5)
	_, err = io.ReadFull(ips, header)
	if string(header) != "PATCH" {
		echan <- fmt.Errorf("Not a valid IPS file!")
		return
	}

	for {
		offs := read3()
		plen := read2()
		if plen == 0 { // RLE patch
			plen = read2()
			val := read1()
			if err == nil {
				out <- NewRlePatch(offs, plen, val)
			}
		} else { // File bytes patch
			buf := make([]byte, plen)
			_, err = io.ReadFull(ips, buf)
			if err == nil {
				out <- NewBytePatch(offs, buf)
			}
		}

		switch {
		case (offs == eof_bytes) && (err == io.EOF):
			return
		case err != nil:
			echan <- errs.Wrap("Error reading ips file:", err)
			return
		}
	}
}

// ReadIps reads all the patches from the given stream, and
// puts them on a channel which it returns to the caller. An
// error channel is also returned, which can be read once the
// patch channel is empty.
func ReadIps(ips io.Reader) (chan Patch, chan error) {
	pchan, echan := make(chan Patch, 100), make(chan error, 1)
	go parseFile(ips, pchan, echan)
	return pchan, echan
}

// WriteIpsChan writes a series of Patches to the given stream.
func WriteIpsChan(tgt io.Writer, src chan Patch) error {
	_, err1 := tgt.Write([]byte("PATCH"))

	var err2 error
	for p := range src {
		if err2 = p.writeIps(tgt); err2 != nil {
			break
		}
	}

	_, err3 := tgt.Write([]byte("EOF"))

	return errs.First("Formatting as IPS: ", err1, err2, err3)
}

// WriteIpsSlice writes a series of Patches to the given stream.
func WriteIpsSlice(tgt io.Writer, src []Patch) error {
	_, err1 := tgt.Write([]byte("PATCH"))

	var err2 error
	for _, p := range src {
		if err2 = p.writeIps(tgt); err2 != nil {
			break
		}
	}

	_, err3 := tgt.Write([]byte("EOF"))

	return errs.First("Formatting as IPS: ", err1, err2, err3)
}
