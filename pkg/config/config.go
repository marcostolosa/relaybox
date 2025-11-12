package config

// Config captures CLI/runtime options for relaybox.
type Config struct {
	RemoteAddr           string
	Interface            string
	Verbose              bool
	UseWinAPI            bool
	PFXPath              string
	PFXPass              string
	EnableSMB            bool
	EnableHTTP           bool
	EnableWinRM          bool
	EnableMSSQL          bool
	EnableMSSQLNamedPipe bool
}
