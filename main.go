package main

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/nu7hatch/gouuid"
	"log"
	"net"
	"time"
	"errors"
	"flag"
	"bytes"
	"net/http"
	"io/ioutil"
	"strings"
	"github.com/malfunkt/iprange"
	"github.com/letitbeat/bpf-parser"
	"encoding/json"
	"strconv"
	"os"
)

var (
	device			= "eth0"
	snapshotLen int32	= 1024 //65535
	promiscuous		= false
	timeout			= 30 * time.Second

	err          error
	handle       *pcap.Handle
	buffer       gopacket.SerializeBuffer
	options      gopacket.SerializeOptions

	flagTarget		= flag.String("t", "10.0.0.252", `Target host(s). Provide a single IP: "1.2.3.4", a CIDR block "1.2.3.0/24", an IP range: "1.2.3-7.4-12", an IP with a wildcard: "1.2.3.*", or a list with any combination: "1.2.3.4, 1.2.3.0/24, ..."`)
	flagProtocol	= flag.String("p", "TCP", "Protocol, TCP, UDP or ICMP")
	flagDstPort  	[]string //flag. Int("dP", 80, `Destination port.`)
	flagIF			= flag.String("it", "TCP 80", `Interesting traffic that should be generated i.e. "TCP port 80" or "UDP 20"`)
	flagSrcIP	string
	)

// Filter used to hold the filter expression to
// applied when generating packets.
type Filter struct {
	Expression string `json:"expression"`
}

// GenerateHandler method which is exposed as web service
// to generate packets given the specified BPF filter.
func GenerateHandler(w http.ResponseWriter, r *http.Request) {

	enableCors(&w)

	if r.Method == "POST" {
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Error reading request body",
				http.StatusInternalServerError)
		}
		var f Filter

		err = json.Unmarshal(body, &f)

		if err != nil {
			http.Error(w, "Error getting data from request",
				http.StatusInternalServerError)
		}

		q, err := bpf.Parse(f.Expression)

		if err != nil {
			http.Error(w, "Error parsing request",
				http.StatusInternalServerError)
		}

		generate(q.Primitives.Qualifiers())

		log.Printf("%s", q.Primitives.Qualifiers())
		log.Printf("%s", string(body))

		host, err := os.Hostname()

		r := struct {
			Response string
			Host string
		}{Response:"Success", Host: host }

		d, err := json.Marshal(r)

		w.Write(d)
	} else {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
	}
}

func enableCors(w *http.ResponseWriter) {
	(*w).Header().Set("Access-Control-Allow-Origin", "*")
}

func main()  {

	mux := http.NewServeMux()
	mux.HandleFunc("/generate", GenerateHandler)

	log.Printf("listening on port %d", 6000)
	log.Fatal(http.ListenAndServe(":6000", mux))

}

func generate(qs map[string][]string)  {

	flag.Parse()

	log.Printf("qualifiers map %v", qs)

	for k, v := range qs {
		log.Printf("%v : %v", k, v)
		switch strings.ToUpper(k) {
		case "TCP", "UDP": 	*flagProtocol = k
							flagDstPort = v
		case "HOST", "DST": *flagTarget = v[0]
		case "SRC": flagSrcIP = v[0]
		}
	}

	if *flagTarget == "" {
		log.Fatal("Missing target (-t 192.168.1.7).")
	}

	device, err = getDevice()
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("About to send packet using device: %s", device)

	// Open device
	handle, err = pcap.OpenLive(device, snapshotLen, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	srcMac := getMacAddr()

	log.Printf("%s", srcMac.String())

	ethernetLayer := &layers.Ethernet{
		SrcMAC: srcMac,
		DstMAC: net.HardwareAddr{0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, //DstMAC: net.HardwareAddr{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
		EthernetType: 0x800,
	}

	var targetAddrs []net.IP
	if *flagTarget != "" {
		addrRange, err := iprange.ParseList(*flagTarget)
		if err != nil {
			log.Fatal("Wrong format for target.")
		}
		targetAddrs = addrRange.Expand()
		if len(targetAddrs) == 0 {
			log.Fatalf("No valid targets given.")
		}
	}

	var srcAddrs []net.IP
	if flagSrcIP != "" {
		addrRange, err := iprange.ParseList(flagSrcIP)
		if err != nil {
			log.Fatal("Wrong format for source address.")
		}
		srcAddrs = addrRange.Expand()
		if len(srcAddrs) == 0 {
			log.Fatalf("No valid source given.")
		}
	}

	// Lets fill out some information
	ipLayer := &layers.IPv4{
		Version: 4,
		IHL:        5,   //uint8
		TOS:        0,   //uint8
		Id:         0,   //uint16
		Flags:      0,   //IPv4Flag
		FragOffset: 0,   //uint16
		TTL:        255, //uint8
		//Protocol:   6,  //IPProtocol UDP(17), TCP(6), ICMP (1) --- fill later
		//SrcIP: net.IP{10, 0, 0, 251}, --- fill later
		//DstIP: net.IP{10, 0, 0, 252}, --- fill later
	}

	var srcIP net.IP

	if len(srcAddrs) > 0 {
		srcIP = srcAddrs[0]    //TODO: check if we are going to allow more than one
	} else {
		srcIP, err = getIP()    // Default set to host's ip
		if err != nil {
			log.Fatal(err)
		}
	}
	log.Printf(" IP: %v", srcIP)

	for _, ip := range targetAddrs {

		if ip.Equal(srcIP) {
			continue
		}

		ipLayer.SrcIP = srcIP
		ipLayer.DstIP = ip

		switch strings.ToUpper(*flagProtocol) {
		case "TCP":
			if len(flagDstPort) > 0 {
				for _, p := range flagDstPort {
					dstPort, err := strconv.Atoi(p)
					if err != nil {
						log.Fatalf("Error converting %v to use a dst port", p)
					}
					sendTCPPacket(ethernetLayer, ipLayer, dstPort, generatePacketId())
				}
			} else {
				sendTCPPacket(ethernetLayer, ipLayer, 80, generatePacketId())
			}

		case "UDP":
			if len(flagDstPort) > 0 {
				for _, p := range flagDstPort {
					dstPort, err := strconv.Atoi(p)
					if err != nil {
						log.Fatalf("Error converting %v to use a dst port", p)
					}
					sendUDPPacket(ethernetLayer, ipLayer, dstPort, generatePacketId())
				}
			} else {
				sendUDPPacket(ethernetLayer, ipLayer, 40, generatePacketId())
			}
			//sendUDPPacket(ethernetLayer, ipLayer, generatePacketId())
		case "ICMP":
			log.Printf("Not implemented yet")
		default:
			log.Printf("Not valid protocol given")
		}

	}
}

func generatePacketId() []byte {
	var u, error = uuid.NewV4()
	if err != nil {
		log.Fatal(error)
	}
	log.Printf("UUID: %v", u)

	return []byte(u.String())
}

func sendTCPPacket(ethernetLayer *layers.Ethernet,
	ipLayer *layers.IPv4,
	dstPort int,
	rawBytes []byte)  {

	log.Printf("Sending TCP Packet to: %v", ipLayer.DstIP)

	ipLayer.Protocol = 6

	tcpLayer := &layers.TCP{
		//SrcPort: layers.TCPPort(4321),
		DstPort: layers.TCPPort(dstPort),
	}
	tcpLayer.SetNetworkLayerForChecksum(ipLayer)

	options.FixLengths = true
	options.ComputeChecksums = true

	// Create the final packet with the layers
	buffer = gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(buffer, options,
		ethernetLayer,
		ipLayer,
		tcpLayer,
		gopacket.Payload(rawBytes),
	)
	if err != nil {
		log.Fatal(err)
	}

	// Send our packet
	err = handle.WritePacketData(buffer.Bytes())
	if err != nil {
		log.Fatal(err)
	}

}

func sendUDPPacket(ethernetLayer *layers.Ethernet,
	ipLayer *layers.IPv4,
	dstPort int,
	rawBytes []byte) {

	log.Printf("Sending UDP Packet to: %v", ipLayer.DstIP)

	ipLayer.Protocol = 17

	udpLayer := &layers.UDP{
		SrcPort: layers.UDPPort(11),
		DstPort: layers.UDPPort(dstPort),
	}

	udpLayer.SetNetworkLayerForChecksum(ipLayer)

	options.FixLengths = true
	options.ComputeChecksums = true

	// Create the final packet with the layers
	buffer = gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(buffer, options,
		ethernetLayer,
		ipLayer,
		udpLayer,
		gopacket.Payload(rawBytes),
	)
	if err != nil {
		log.Fatal(err)
	}

	// Send our packet
	err = handle.WritePacketData(buffer.Bytes())
	if err != nil {
		log.Fatal(err)
	}

}

func getIP() (net.IP, error) {

	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, i := range ifaces {
		addrs, err := i.Addrs()
		if err != nil {
			return nil, err
		}

		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() {
				continue
			}
			ip = ip.To4()
			if ip == nil {
				continue // not an ipv4 address
			}
			return ip, nil
		}
	}

	return nil, errors.New("it seems that you are not connected any network")
}

// getMacAddr gets the MAC hardware
// address of the host machine
func getMacAddr() (addr net.HardwareAddr) {
	interfaces, err := net.Interfaces()
	if err == nil {
		for _, i := range interfaces {
			if i.Flags&net.FlagUp != 0 && bytes.Compare(i.HardwareAddr, nil) != 0 {
				// Don't use random as we have a real address
				addr = i.HardwareAddr
				break
			}
		}
	}
	return
}

func getDevice() (string, error) {

	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	for _, i := range ifaces {

		if i.Flags&net.FlagUp == 0 {
			continue // interface down
		}
		if i.Flags&net.FlagLoopback != 0 {
			continue // loopback interface
		}

		return i.Name, nil
	}

	return "", errors.New("no interface found")
}
