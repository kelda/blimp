package dns

import (
	"net"
	"strings"
	"sync"

	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/kelda-inc/blimp/pkg/metadata"
)

const dnsTTL = 60 // Seconds

type dnsTable struct {
	server dns.Server

	recordLock sync.Mutex
	records    map[string]net.IP
}

func Run(kubeClient kubernetes.Interface, namespace string) {
	table := makeTable()

	// There could be multiple messages depending on how listenAndServe is
	// implemented.  We don't want anyone to block, so we make a bit of a buffer.
	errChan := make(chan error, 8)
	table.server.NotifyStartedFunc = func() { errChan <- nil }
	go func() { errChan <- listenAndServe(table) }()

	if err := <-errChan; err != nil {
		log.WithError(err).Error("Failed to start DNS server")
		return
	}

	log.Info("Started DNS Server")

	podsClient := kubeClient.CoreV1().Pods(namespace)
	watcher, err := podsClient.Watch(metav1.ListOptions{
		LabelSelector: "blimp.customerPod=true",
	})
	if err != nil {
		log.WithError(err).Error("Failed to watch pods")
		return
	}

	for range watcher.ResultChan() {
		pods, err := podsClient.List(metav1.ListOptions{
			LabelSelector: "blimp.customerPod=true",
		})
		if err != nil {
			log.WithError(err).Error("Failed to list pods")
			continue
		}

		records := podsToDNS(pods.Items)
		table.recordLock.Lock()
		table.records = records
		table.recordLock.Unlock()
	}
}

func (table *dnsTable) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	defer w.Close()

	resp := table.genResponse(req)
	if resp == nil {
		return
	}

	if err := w.WriteMsg(resp); err != nil {
		log.WithError(err).Error("Failed to send DNS response")
	}
}

func (table *dnsTable) genResponse(req *dns.Msg) *dns.Msg {
	resp := &dns.Msg{}
	if len(req.Question) != 1 {
		return resp.SetRcode(req, dns.RcodeNotImplemented)
	}

	q := req.Question[0]
	// If the request is for an IPv6 address, simply return an empty answer to
	// indicate that there may be answers for other query types, such as IPv4.
	if q.Qtype == dns.TypeAAAA {
		return resp.SetReply(req)
	}

	if q.Qclass != dns.ClassINET || q.Qtype != dns.TypeA {
		return resp.SetRcode(req, dns.RcodeNotImplemented)
	}

	ips := table.lookupA(q.Name)
	if len(ips) == 0 {
		// Even though the client asked for a Kelda hostname that we know
		// nothing about, it's possible we'll learn about it in the future.  For
		// now, we'll just not respond, the client will time out, and try again
		// later.  Hopefully by then we have a response for them -- or if not,
		// eventually they'll give up.
		//
		// XXX: The above logic is correct for Kelda hostname, but
		// we're also doing the same thing for failures to resolve external
		// hosts.  This isn't entirely correct, it would be much better to return
		// whatever upstream gave us in case of a failure.
		return nil
	}

	resp.SetReply(req)
	for _, ip := range ips {
		resp.Answer = append(resp.Answer, &dns.A{
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    dnsTTL,
			},
			A: ip,
		})
	}
	return resp
}

func (table *dnsTable) lookupA(name string) []net.IP {
	name = strings.TrimRight(strings.ToLower(name), ".")
	isInternalHostname := strings.Count(name, ".") == 0
	if isInternalHostname {
		table.recordLock.Lock()
		ip := table.records[name]
		table.recordLock.Unlock()
		if ip == nil {
			return nil
		}
		return []net.IP{ip}
	}

	ipStrs, err := lookupHost(name)
	if err != nil {
		log.WithError(err).Debug("Failed to lookup external record: ", name)
		return nil
	}

	var ips []net.IP
	for _, ipStr := range ipStrs {
		if ip := net.ParseIP(ipStr); ip != nil && ip.To4() != nil {
			ips = append(ips, ip)
		}
	}
	return ips
}

func makeTable() *dnsTable {
	tbl := &dnsTable{
		server: dns.Server{
			Addr: "0.0.0.0:53",
			Net:  "udp",
		},
	}
	tbl.server.Handler = tbl
	return tbl
}

func podsToDNS(pods []corev1.Pod) map[string]net.IP {
	records := map[string]net.IP{}
	for _, pod := range pods {
		ip := net.ParseIP(pod.Status.PodIP)
		if ip == nil {
			continue
		}

		records[strings.ToLower(pod.Name)] = ip

		// Add aliases to DNS.
		aliases, ok := pod.Annotations[metadata.AliasesKey]
		if !ok {
			continue
		}

		for _, alias := range metadata.ParseAliases(aliases) {
			records[strings.ToLower(alias)] = ip
		}
	}
	return records
}

var listenAndServe = func(table *dnsTable) error {
	return table.server.ListenAndServe()
}

var lookupHost = net.LookupHost
