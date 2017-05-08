package main

import (
	"bufio"
	"fmt"
	"os"

	"github.com/rwtodd/Go.IpsPatch/ips"
)

func process(ipsf, srcf, tgtf string) error {
	// open the IPS file and start the reader
	infile, err := os.Open(ipsf)
	if err != nil {
		return fmt.Errorf("Opening IPS file: %v\n", err)
	}
	defer infile.Close()
	br := bufio.NewReader(infile)

	pchan, echan := ips.ReadIps(br)

	// copy the source to the new name
	if err = copyFileContents(srcf, tgtf); err != nil {
		return fmt.Errorf("File copy: %v\n", err)
	}

	// open the target for patching
	outfile, err := os.OpenFile(tgtf, os.O_WRONLY, 0666)
	if err != nil {
		return fmt.Errorf("Opening output file: %v\n", err)
	}
	defer outfile.Close()

	// drain the channel, applying patches
	idx := 0
	for p := range pchan {
		idx++
		fmt.Printf("%d: %v\n", idx, p)
		if err := p.ApplyTo(outfile); err != nil {
			return fmt.Errorf("Applying patches: %v\n", err)
		}
	}

	return <-echan
}

func main() {
	// check the arguments
	if len(os.Args) != 4 {
		fmt.Fprintf(os.Stderr,
			"Usage: %s patchfile orig newfile\n",
			os.Args[0])
		os.Exit(1)
	}

	if err := process(os.Args[1], os.Args[2], os.Args[3]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
