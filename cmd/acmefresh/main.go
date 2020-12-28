package main

// acmefresh is a RFC 8555 (ACME) compliant tool
// that orders a new certificates (if none exist)
// or renews a certificate which will expire within a configured time.
//
// Sequence of operation below:
// - get client account key from filesystem
// - if not exist
//   - create it
// - listen for /.well-known/acme-challenge/<token> requests
// - authenticate to acme-compliant server (using client account key)
// - examine domain cert
// - if not exist or will expire within configured time,
//   - authorize a new cert
//   - handle the hand-shake and http-01 challenge (/.well-known/acme-challenge/<token> requests)
//   - write cert to expected file location and copy to a date-stamped file
// - exit
//
// This tool will not do retries beyond those done by the underlying acme library.
// Instead, it can be run again if there is an error, and that will retry until no errors.
//
// Typical usage is for it to be run as a scheduled job every 2 weeks or so.
//
// Closed Questions:
// - should we depend on stack traces, or use err messages alone?
//   Answer: Use stack traces (for easy debugging)
// - to store certs as k8s secret, just run kubectl after running this tool successfully
//   For HAProxy, the configMap value ssl-certificate is a k8s secret combining key and cert
//   https://www.haproxy.com/documentation/kubernetes/latest/configuration/
// - How do we know what files to use? Can we look at certbot instructions?
//   Yes, see https://certbot.eff.org/docs/using.html#where-are-my-certificates

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ugorji/go-common/flagutil"

	"golang.org/x/crypto/acme"
)

type Manager struct {
	Client          *acme.Client
	Email           string
	ExtraExtensions []pkix.Extension
	httpTokens      map[string][]byte
	Domains         []string
	CertDir         string
	CertBaseName    string
	KeyFile         string
	ServerPort      int
	ExpireWithin    time.Duration
	certSigner      *ecdsa.PrivateKey // crypto.Signer
	certSignerBytes []byte
	mu              sync.RWMutex
	newKey4CSR      bool // use client key to sign cert
}

func onerr(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {
	// defaultACMEDirectory is the default ACME Directory URL
	const defaultACMEDirectory = "https://acme-v02.api.letsencrypt.org/directory"

	var mgr = Manager{
		httpTokens: make(map[string][]byte),
		Client: &acme.Client{
			DirectoryURL: defaultACMEDirectory,
			UserAgent:    "acmefresh",
		},
	}

	var revoke bool

	flag.StringVar(&mgr.KeyFile, "keyfile", "acmefresh.key", "acme client key file")
	flag.StringVar(&mgr.Email, "email", "acmefresh@ugorji.net", "contact email")
	flag.StringVar(&mgr.CertDir, "certdir", ".", "directory where certs are placed")
	flag.StringVar(&mgr.CertBaseName, "cert", "latest", "base name for cert file (without extension)")
	flag.StringVar(&mgr.Client.DirectoryURL, "acme-url", defaultACMEDirectory, "ACME Directory URL")
	flag.IntVar(&mgr.ServerPort, "port", 9876, "listen port for well-known challenge")
	flag.BoolVar(&mgr.newKey4CSR, "newkey", false, "use new key for signing cert, not client account key")
	flag.DurationVar(&mgr.ExpireWithin, "expire", time.Hour*24*7*6, "time within which to renew certificate")
	flag.Var((*flagutil.StringsNoDupFlagValue)(&mgr.Domains), "domain", "domains")
	flag.BoolVar(&revoke, "revoke", false, "revoke certificate")

	flag.Parse()

	fi, err := os.Stat(mgr.CertDir)
	onerr(err)
	if !fi.IsDir() {
		onerr(fmt.Errorf("The cert dir: %s, is not a directory", mgr.CertDir))
	}

	if !revoke && (len(mgr.Domains) == 0 || mgr.certOK()) {
		return
	}

	ctx := context.Background()

	var key []byte
	fi, err = os.Stat(mgr.KeyFile)
	if err == nil {
		key, err = ioutil.ReadFile(mgr.KeyFile)
		onerr(err)
		priv, _ := pem.Decode(key)
		if priv == nil || !strings.Contains(priv.Type, "PRIVATE") {
			onerr(errors.New("invalid client account key"))
		}
		mgr.certSignerBytes = priv.Bytes
		mgr.certSigner, err = x509.ParseECPrivateKey(mgr.certSignerBytes)
	} else if os.IsNotExist(err) {
		mgr.certSigner, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		onerr(err)
		mgr.certSignerBytes, err = x509.MarshalECPrivateKey(mgr.certSigner)
		onerr(err)
		key = mgr.certSignerBytes
		var buf bytes.Buffer
		pb := &pem.Block{Type: "EC PRIVATE KEY", Bytes: key}
		err = pem.Encode(&buf, pb)
		onerr(err)
		key = buf.Bytes()
		err = ioutil.WriteFile(mgr.KeyFile, key, 0644)
	}
	onerr(err)

	mgr.Client.Key = mgr.certSigner

	if revoke {
		mgr.revokeCert(ctx)
		return
	}

	if mgr.newKey4CSR {
		mgr.certSigner, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		onerr(err)
		mgr.certSignerBytes, err = x509.MarshalECPrivateKey(mgr.certSigner)
		onerr(err)
	}

	a, err := mgr.Client.GetReg(ctx, "")
	if err != nil {
		a = &acme.Account{Contact: []string{"mailto:" + mgr.Email}}
		a, err = mgr.Client.Register(ctx, a, func(string) bool { return true })
		if err == nil || err == acme.ErrAccountAlreadyExists { // ignore
		} else if ae, ok := err.(*acme.Error); ok && ae.StatusCode == http.StatusConflict { // ignore
		} else {
			onerr(err)
		}
	}

	httpHdlr := func(w http.ResponseWriter, r *http.Request) {
		const pfx = "/.well-known/acme-challenge/"
		if !strings.HasPrefix(r.URL.Path, pfx) {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		// token := r.URL.Path[len(pfx):]
		mgr.mu.RLock()
		val, ok := mgr.httpTokens[r.URL.Path]
		mgr.mu.RUnlock()
		if !ok {
			http.Error(w, "Token value not found", http.StatusNotFound)
			return
		}
		w.Write(val)
	}
	srv := &http.Server{
		Addr:           ":" + strconv.Itoa(mgr.ServerPort),
		Handler:        http.HandlerFunc(httpHdlr),
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}
	ln, err := net.Listen("tcp", srv.Addr)
	onerr(err)
	go srv.Serve(ln)
	defer func() { srv.Shutdown(ctx) }()

	// return mgr.doCertsAsync(domains)
	der := mgr.orderCert(ctx)
	mgr.writeCert(der)
	return
}

func (m *Manager) certOK() (ok bool) {
	// if cert exists, and expires more than configured time away, then do nothing
	var leaf *x509.Certificate
	n := filepath.Join(m.CertDir, m.CertBaseName+".crt")
	b, err := ioutil.ReadFile(n)
	if err != nil {
		return
	}
	pb, _ := pem.Decode(b)
	var k []*x509.Certificate
	if k, err = x509.ParseCertificates(pb.Bytes); err == nil && len(k) > 0 {
		leaf = k[0]
		if leaf.NotAfter.Sub(time.Now()) > m.ExpireWithin {
			ok = true
		}
	}
	if ok {
		ok = len(m.Domains) == len(leaf.DNSNames)
	}
	if ok {
		sort.Strings(m.Domains)
		sort.Strings(leaf.DNSNames)
		for i := 0; i < len(m.Domains); i++ {
			if m.Domains[i] != leaf.DNSNames[i] {
				ok = false
				break
			}
		}
	}
	return
}

func (m *Manager) writeCert(der [][]byte) {
	var buf bytes.Buffer
	var pb = &pem.Block{Type: "CERTIFICATE", Bytes: der[0]}
	onerr(pem.Encode(&buf, pb))
	var leafLen = buf.Len()
	for _, ss := range der[1:] {
		pb.Bytes = ss
		onerr(pem.Encode(&buf, pb))
	}
	var keyPEM, certPEM, leafPEM, chainPEM, allPEM []byte
	keyPEM = m.certSignerBytes          // priv key
	certPEM = buf.Bytes()               // leaf + chain
	leafPEM = certPEM[:leafLen]         // leaf
	chainPEM = certPEM[leafLen:]        // chain
	allPEM = append(certPEM, keyPEM...) // leaf + chain + priv key

	var ts = time.Now().Format("2006_01_02.") // Mon Jan 2 15:04:05 -0700 MST 2006
	var fname = func(s string) string { return filepath.Join(m.CertDir, m.CertBaseName+"."+s) }

	onerr(ioutil.WriteFile(fname("crt"), certPEM, 0644))
	onerr(ioutil.WriteFile(fname("leaf.crt"), leafPEM, 0644))
	onerr(ioutil.WriteFile(fname("chain.crt"), chainPEM, 0644))
	// files containing private key MUST be stored privately and securely (hence perm: 0600 below)
	onerr(ioutil.WriteFile(fname("crt.key"), keyPEM, 0600))
	onerr(ioutil.WriteFile(fname("pem"), allPEM, 0600))
	onerr(ioutil.WriteFile(fname(ts+"pem"), allPEM, 0600))
}

// orderCert runs the identifier (domains) order-based authorization flow for RFC compliant CAs
func (m *Manager) orderCert(ctx context.Context) (der [][]byte) {
	domains := m.Domains
	o, err := m.Client.AuthorizeOrder(ctx, acme.DomainIDs(domains...))
	onerr(err)
	// Remove all hanging authorizations to reduce rate limit quotas after we're done.
	defer func(urls []string) {
		for _, u := range urls {
			z, err := m.Client.GetAuthorization(ctx, u)
			if err == nil && z.Status == acme.StatusPending {
				m.Client.RevokeAuthorization(ctx, u)
			}
		}
	}(o.AuthzURLs)

	// Check if there's actually anything we need to do.
	switch o.Status {
	case acme.StatusReady: // Already authorized.
		return
	case acme.StatusPending: // Continue normal Order-based flow.
	default:
		onerr(fmt.Errorf("invalid new order status %q; order URL: %q", o.Status, o.URI))
	}

	// Satisfy all pending authorizations.
	for _, zurl := range o.AuthzURLs {
		z, err := m.Client.GetAuthorization(ctx, zurl)
		onerr(err)
		if z.Status != acme.StatusPending { // We are interested only in pending authorizations.
			continue
		}

		var chal *acme.Challenge
		for _, c := range z.Challenges {
			if c.Type == "http-01" {
				chal = c
				break
			}
		}
		if chal == nil {
			onerr(fmt.Errorf("no http-01 challenge to satisfy '%s' for domains %v: ", z.URI, domains))
		}

		// Respond to the challenge and wait for validation result.
		resp, err := m.Client.HTTP01ChallengeResponse(chal.Token)
		onerr(err)

		p := m.Client.HTTP01ChallengePath(chal.Token)
		m.mu.Lock()
		m.httpTokens[p] = []byte(resp)
		m.mu.Unlock()
		defer func() {
			m.mu.Lock()
			delete(m.httpTokens, p)
			m.mu.Unlock()
		}()

		_, err = m.Client.Accept(ctx, chal)
		onerr(err)
		_, err = m.Client.WaitAuthorization(ctx, z.URI)
		onerr(err)
	}

	o, err = m.Client.WaitOrder(ctx, o.URI)
	onerr(err)

	req := &x509.CertificateRequest{
		// Subject:         pkix.Name{CommonName: domain}, // no common name - use SAN via DNSNames instead
		ExtraExtensions: m.ExtraExtensions,
		DNSNames:        domains,
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, req, m.certSigner)
	onerr(err)

	der, _, err = m.Client.CreateOrderCert(ctx, o.FinalizeURL, csr, true)
	onerr(err)
	if len(der) == 0 {
		onerr(errors.New("missing certificate"))
	}
	return
}

func (m *Manager) revokeCert(ctx context.Context) {
	fname := func(s string) string { return filepath.Join(m.CertDir, m.CertBaseName+"."+s) }
	der := func(s string) []byte {
		b, err := ioutil.ReadFile(fname(s))
		onerr(err)
		pb, _ := pem.Decode(b)
		return pb.Bytes
	}
	key := der("crt.key")
	leaf := der("leaf.crt")
	signer, err := x509.ParseECPrivateKey(key)
	onerr(err)
	onerr(m.Client.RevokeCert(ctx, signer, leaf, acme.CRLReasonUnspecified))
	for _, s := range []string{"crt", "leaf.crt", "chain.crt", "crt.key", "pem"} {
		onerr(os.Remove(fname(s)))
	}
}
