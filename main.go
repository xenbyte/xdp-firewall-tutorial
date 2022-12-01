package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"

	"github.com/dropbox/goebpf"
)

func main() {

	// Specify Interface Name
	interfaceName := "lo"
	// IP BlockList
	// Add the IPs you want to be blocked
	ipList := []string{
		"8.8.8.8",
	}

	// Load XDP Into App
	bpf := goebpf.NewDefaultEbpfSystem()
	err := bpf.LoadElf("bpf/xdp_drop.elf")
	if err != nil {
		log.Fatalf("LoadELF() failed: %s", err)
	}
	blacklist := bpf.GetMapByName("blacklist")
	if blacklist == nil {
		log.Fatalf("eBPF map 'blacklist' not found\n")
	}
	xdp := bpf.GetProgramByName("firewall")
	if xdp == nil {
		log.Fatalln("Program 'firewall' not found in Program")
	}
	err = xdp.Load()
	if err != nil {
		fmt.Printf("xdp.Attach(): %v", err)
	}
	err = xdp.Attach(interfaceName)
	if err != nil {
		log.Fatalf("Error attaching to Interface: %s", err)
	}

	BlockIPAddress(ipList, blacklist)

	defer xdp.Detach()
	ctrlC := make(chan os.Signal, 1)
	signal.Notify(ctrlC, os.Interrupt)
	log.Println("XDP Program Loaded successfuly into the Kernel.")
	log.Println("Press CTRL+C to stop.")
	<-ctrlC

}

// The Function That adds the IPs to the blacklist map
func BlockIPAddress(ipAddreses []string, blacklist goebpf.Map) error {
	for index, ip := range ipAddreses {
		fmt.Printf("\t%s\n", ip)
		err := blacklist.Insert(goebpf.CreateLPMtrieKey(ip), index)
		if err != nil {
			return err
		}
	}
	return nil
}
