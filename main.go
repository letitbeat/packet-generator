package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/letitbeat/bpf-parser"
	"github.com/malfunkt/iprange"
	uuid "github.com/nu7hatch/gouuid"
)

var (
	device            = "eth0"
	snapshotLen int32 = 1024 //65535
	promiscuous       = false
	timeout           = 30 * time.Second

	err     error
	handle  *pcap.Handle
	buffer  gopacket.SerializeBuffer
	options gopacket.SerializeOptions

	flagTarget   = flag.String("t", "10.0.0.252", `Target host(s). Provide a single IP: "1.2.3.4", a CIDR block "1.2.3.0/24", an IP range: "1.2.3-7.4-12", an IP with a wildcard: "1.2.3.*", or a list with any combination: "1.2.3.4, 1.2.3.0/24, ..."`)
	flagProtocol = flag.String("p", "TCP", "Protocol, TCP, UDP or ICMP")
	flagDstPort  []string //flag. Int("dP", 80, `Destination port.`)
	flagIF       = flag.String("it", "TCP 80", `Interesting traffic that should be generated i.e. "TCP port 80" or "UDP 20"`)
	flagSrcIP    string
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
			Host     string
		}{Response: "Success", Host: host}

		d, err := json.Marshal(r)

		w.Write(d)
	} else {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
	}
}

func enableCors(w *http.ResponseWriter) {
	(*w).Header().Set("Access-Control-Allow-Origin", "*")
}

func main() {

	mux := http.NewServeMux()
	mux.HandleFunc("/generate", GenerateHandler)

	log.Printf("listening on port %d", 6000)
	log.Fatal(http.ListenAndServe(":6000", mux))

}

type protocol int8

const (
	UDP  protocol = 0
	TCP  protocol = 1
	ICMP protocol = 2
)

type npingParams struct {
	ports string
	src   string
	dst   string
	prot  protocol
}

func generate(qs map[string][]string) {

	flag.Parse()

	log.Printf("qualifiers map %v", qs)

	for k, v := range qs {
		log.Printf("%v : %v", k, v)
		switch strings.ToUpper(k) {
		case "TCP", "UDP":
			*flagProtocol = k
			flagDstPort = v
		case "HOST", "DST":
			*flagTarget = v[0]
		case "SRC":
			flagSrcIP = v[0]
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

	var srcIP net.IP

	if len(srcAddrs) > 0 {
		srcIP = srcAddrs[0] //TODO: check if we are going to allow more than one
	} else {
		srcIP, err = getIP() // Default set to host's ip
		if err != nil {
			log.Fatal(err)
		}
	}
	log.Printf(" IP: %v", srcIP)

	params := npingParams{
		ports: strings.Join(flagDstPort[:], ","),
		dst:   *flagTarget,
		src:   flagSrcIP,
	}

	for _, ip := range targetAddrs {

		if ip.Equal(srcIP) {
			continue
		}

		switch strings.ToUpper(*flagProtocol) {
		case "TCP":
			params.prot = TCP
		case "UDP":
			params.prot = UDP
		case "ICMP":
			log.Printf("Not implemented yet")
		default:
			log.Printf("Not valid protocol given")
		}
		executeNping(params, string(generatePacketId()))
	}

}

func executeNping(params npingParams, uuid string) {

	args := []string{"-c", "1", "--data-string", uuid} // default args to 1 packet only and payload uuid
	switch params.prot {
	case TCP:
		args = append(args, "--tcp")
	case UDP:
		args = append(args, "--udp")
	default:
		args = append(args, "--tcp")
	}

	args = append(args, []string{"-p", params.ports}...)
	args = append(args, params.dst)

	log.Printf("CMD: %v", args)
	cmd := exec.Command("nping", args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		log.Printf("error executing nping: %s", err.Error())
	}
	log.Printf("Execution output: %s", string(out.Bytes()))
}

func generatePacketId() []byte {
	var u, error = uuid.NewV4()
	if err != nil {
		log.Fatal(error)
	}
	log.Printf("UUID: %v", u)

	return []byte(u.String())
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
