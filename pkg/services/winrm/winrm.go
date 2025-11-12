package winrm

import (
	"fmt"
	"io"
	"net"
	"strings"
	"sync/atomic"

	"relaybox/pkg/system/executil"
	"relaybox/pkg/system/logging"
)

type WinRM struct {
	Listeners      []net.Listener
	ExePath        string
	LocalAddresses []string
	RemoteAddr     string
	WinAPI         bool
	Logger         *logging.Logger
}

func NewWinRM(exePath string, localAddresses []string, remoteAddr string, verbose bool) *WinRM {
	return &WinRM{
		Listeners:      []net.Listener{},
		ExePath:        exePath,
		LocalAddresses: localAddresses,
		RemoteAddr:     remoteAddr,
		WinAPI:         true,
		Logger:         logging.NewLogger("WinRM", verbose),
	}
}

func (w *WinRM) GetPort() string {
	return ":5985"
}

func (w *WinRM) GetServiceName() string {
	return "WinRM"
}

func (w *WinRM) Start() int {
	w.Logger.Log("Binding HTTP services to localhost (includes WinRM)...")
	err := executil.RunCommandPowershell("netsh http add iplisten ipaddress=127.0.0.1")
	if err != nil {
		w.Logger.Log(fmt.Sprintf("Failed to rebind HTTP services to localhost %s", err))
		return 1
	}
	w.Logger.Log("Restarting WinRM service")
	err = executil.RunCommandPowershell("Restart-Service WinRM")
	if err != nil {
		w.Logger.Log(fmt.Sprintf("Failed to restart WinRM service. %s", err))
		return 1
	}

	for _, addr := range w.LocalAddresses {
		listener, err := net.Listen("tcp", addr+w.GetPort())
		if err != nil {
			w.Logger.Verbose(fmt.Sprintf("Failed to listen on %s: %v", addr, err))
			continue
		}
		w.Listeners = append(w.Listeners, listener)
		w.Logger.Log(fmt.Sprintf("Proxy listening on %s, forwarding WinRM to %s", addr, w.RemoteAddr))
	}

	if len(w.Listeners) == 0 {
		w.Logger.Log("No listeners created, exiting...")
		return 1
	}

	w.createWinRMFirewallRule()

	for _, listener := range w.Listeners {
		go w.listenerHandler(listener)
	}

	return 0
}

func (w *WinRM) Stop() {
	for _, listener := range w.Listeners {
		if err := listener.Close(); err != nil {
			w.Logger.Log(fmt.Sprintf("Error closing listener: %v", err))
		}
	}
	w.Logger.Log("Removing WinRM binding to localhost")
	err := executil.RunCommandPowershell("netsh http delete iplisten ipaddress=127.0.0.1")
	if err != nil {
		w.Logger.Log(fmt.Sprintf("Failed to rebind HTTP services to all interfaces %s", err))
	}
	w.Logger.Log("Restarting WinRM service")
	err = executil.RunCommandPowershell("Restart-Service WinRM")
	if err != nil {
		w.Logger.Log(fmt.Sprintf("Failed to restart WinRM service. %s", err))
	}
	w.removeWinRMFirewallRule()
}

// PROXY HANDLING

func (w *WinRM) listenerHandler(listener net.Listener) {
	history := []string{}
	for {
		conn, err := listener.Accept()
		if err != nil {
			w.Logger.Verbose(fmt.Sprintf("Accept error: %v", err))
			return
		}

		w.Logger.Log(fmt.Sprintf("Accepted WinRM connection from %s", conn.RemoteAddr()))
		client := strings.Split(conn.RemoteAddr().String(), ":")[0]

		target := w.RemoteAddr + w.GetPort()
		seenBefore := false
		for _, h := range history {
			if h == client {
				seenBefore = true
				break
			}
		}
		if seenBefore {
			target = "127.0.0.1" + w.GetPort()
			w.Logger.Verbose(fmt.Sprintf("Forwarding to local WinRM for client %s", client))
		} else {
			history = append(history, client)
			w.Logger.Verbose(fmt.Sprintf("Forwarding to remote WinRM for client %s", client))
		}

		go w.handleConnection(conn, target, seenBefore)
	}
}

func (w *WinRM) handleConnection(localConn net.Conn, remoteAddr string, isLocal bool) {
	defer localConn.Close()

	remoteConn, err := net.Dial("tcp", remoteAddr)
	if err != nil {
		w.Logger.Verbose(fmt.Sprintf("Failed to connect to %s: %v", remoteAddr, err))
		return
	}
	defer remoteConn.Close()

	var closed uint32
	go func() {
		if _, err := w.copyStream(remoteConn, localConn, &closed); err != nil {
			w.Logger.Verbose(fmt.Sprintf("Error proxying client→server: %v", err))
		}
		atomic.StoreUint32(&closed, 1)
	}()

	if _, err := w.copyStream(localConn, remoteConn, &closed); err != nil {
		w.Logger.Verbose(fmt.Sprintf("Error proxying server→client: %v", err))
		atomic.StoreUint32(&closed, 1)
	}
}

func (w *WinRM) copyStream(dst io.Writer, src io.Reader, closeFlag *uint32) (int64, error) {
	buf := make([]byte, 32*1024)
	var total int64

	for atomic.LoadUint32(closeFlag) == 0 {
		n, err := src.Read(buf)
		if n > 0 {
			data := buf[:n]
			written, werr := dst.Write(data)
			if werr != nil {
				return total, werr
			}
			if written != len(data) {
				return total, io.ErrShortWrite
			}
			total += int64(written)
		}

		if err != nil {
			if err == io.EOF {
				return total, nil
			}
			return total, err
		}
	}
	return total, nil
}

func (w *WinRM) createWinRMFirewallRule() {
	w.Logger.Log("Creating WinRM firewall rule...")
	localAddressesStr := ""
	for _, addr := range w.LocalAddresses {
		localAddressesStr += fmt.Sprintf(`"%s",`, addr)
	}
	localAddressesStr = strings.TrimSuffix(localAddressesStr, ",")
	ruleCmd := fmt.Sprintf(
		`New-NetFirewallRule -DisplayName "WinRM" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 5985 -LocalAddress @(%s) -Program "%s"`,
		localAddressesStr,
		w.ExePath,
	)
	executil.RunCommandPowershell(ruleCmd)
	w.Logger.Log("WinRM firewall rule created.")
}

func (w *WinRM) removeWinRMFirewallRule() {
	w.Logger.Log("Removing WinRM firewall rule...")
	executil.RunCommandPowershell(`Remove-NetFirewallRule -DisplayName "WinRM"`)
	w.Logger.Log("WinRM firewall rule removed.")
}
