package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"relaybox/pkg/app"
	"relaybox/pkg/config"
	"syscall"
)

func main() {
	var cfg config.Config

	flag.BoolVar(&cfg.EnableSMB, "smb", false, "Enable SMB relay")
	flag.BoolVar(&cfg.UseWinAPI, "winapi", false, "Use Windows API to shut down smb service, default will kill with powershell command")
	flag.BoolVar(&cfg.EnableHTTP, "http", false, "Enable HTTP relay")
	flag.BoolVar(&cfg.EnableWinRM, "winrm", false, "Enable WinRM relay")
	flag.BoolVar(&cfg.EnableMSSQL, "mssql", false, "Enable MSSQL relay")
	flag.BoolVar(&cfg.EnableMSSQLNamedPipe, "mssql-smb", false, "Enable MSSQL relay via named pipes, will also run smb proxy")
	flag.StringVar(&cfg.Interface, "iface", "", "Specific interface to bind rogue to, defaults to all interfaces")
	flag.StringVar(&cfg.RemoteAddr, "raddr", "", "Remote host to forward to (will match port bound for rogue service)")
	flag.BoolVar(&cfg.Verbose, "verbose", false, "Enable verbose logging")
	flag.StringVar(&cfg.PFXPath, "pfx", "", "File path of PFX file to run HTTPS proxy")
	flag.StringVar(&cfg.PFXPass, "pfx-pass", "", "Password of PFX file to run HTTPS proxy")
	flag.Parse()

	if cfg.RemoteAddr == "" {
		flag.Usage()
		os.Exit(1)
	}

	exePath, err := os.Executable()
	if err != nil {
		log.Fatalf("Error getting executable path: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := app.Run(ctx, exePath, cfg); err != nil {
		log.Fatal(err)
	}
}
