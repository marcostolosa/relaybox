package app

import (
	"context"
	"fmt"
	"log"
	"os"

	"relaybox/pkg/config"
	"relaybox/pkg/services/httprelay"
	"relaybox/pkg/services/mssql"
	"relaybox/pkg/services/smb"
	"relaybox/pkg/services/winrm"
	"relaybox/pkg/system/network"
)

type Service interface {
	GetPort() string
	GetServiceName() string
	Start() int
	Stop()
}

// Run wires up relay services based on the provided configuration and blocks until ctx is canceled.
func Run(ctx context.Context, exePath string, cfg config.Config) error {
	if cfg.RemoteAddr == "" {
		return fmt.Errorf("remote address is required")
	}

	localAddrs, err := resolveAddresses(cfg)
	if err != nil {
		return err
	}
	if len(localAddrs) == 0 {
		return fmt.Errorf("no local addresses found")
	}

	services := buildServices(exePath, localAddrs, cfg)
	if len(services) == 0 {
		return fmt.Errorf("no services enabled")
	}

	log.Printf("Local addresses: %v", localAddrs)
	log.Printf("Remote address: %s", cfg.RemoteAddr)

	started := startServices(services)
	if len(started) == 0 {
		return fmt.Errorf("all services failed to start")
	}

	<-ctx.Done()
	log.Println("Shutdown requested, stopping services...")
	for _, svc := range started {
		log.Printf("Stopping %s on %s", svc.GetServiceName(), svc.GetPort())
		svc.Stop()
	}
	log.Println("Shutdown complete")
	return nil
}

func resolveAddresses(cfg config.Config) ([]string, error) {
	if cfg.Interface == "" {
		return network.GetAllIPs()
	}
	addr, err := network.GetIPByInterface(cfg.Interface)
	if err != nil {
		return nil, err
	}
	return []string{addr}, nil
}

func buildServices(exePath string, localAddresses []string, cfg config.Config) []Service {
	var services []Service

	namedPipes := cfg.EnableMSSQLNamedPipe
	enableSMB := cfg.EnableSMB || namedPipes

	if namedPipes {
		log.Println("MSSQL Named Pipe relay enabled")
		services = append(services, mssql.NewMSSQL(exePath, localAddresses, cfg.RemoteAddr, true, cfg.Verbose))
	}
	if enableSMB {
		log.Println("SMB relay enabled")
		services = append(services, smb.NewSMB(exePath, localAddresses, cfg.RemoteAddr, cfg.UseWinAPI, cfg.Verbose))
	}
	if cfg.EnableHTTP {
		log.Println("HTTP relay enabled")
		hostname, err := os.Hostname()
		if err != nil {
			log.Println("Error getting hostname:", err)
			hostname = ""
		}
		services = append(services, httprelay.NewHTTP(exePath, localAddresses, cfg.RemoteAddr, hostname, cfg.PFXPath, cfg.PFXPass, cfg.Verbose))
	}
	if cfg.EnableWinRM {
		log.Println("WinRM relay enabled")
		services = append(services, winrm.NewWinRM(exePath, localAddresses, cfg.RemoteAddr, cfg.Verbose))
	}
	if cfg.EnableMSSQL && !namedPipes {
		log.Println("MSSQL relay enabled")
		services = append(services, mssql.NewMSSQL(exePath, localAddresses, cfg.RemoteAddr, false, cfg.Verbose))
	}
	return services
}

func startServices(services []Service) []Service {
	var started []Service
	for _, service := range services {
		log.Printf("Starting rogue %s on %s", service.GetServiceName(), service.GetPort())
		if service.Start() == 1 {
			service.Stop()
			log.Printf("Failed to start %s on %s", service.GetServiceName(), service.GetPort())
			continue
		}
		log.Printf("Started rogue %s on %s!", service.GetServiceName(), service.GetPort())
		started = append(started, service)
	}
	return started
}
