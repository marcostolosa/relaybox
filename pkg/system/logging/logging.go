package logging

import "log"

// Logger provides simple service-scoped logging with optional verbosity.
type Logger struct {
	serviceName  string
	verboseLevel bool
}

func NewLogger(serviceName string, verbose bool) *Logger {
	return &Logger{
		serviceName:  serviceName,
		verboseLevel: verbose,
	}
}

func (l *Logger) Log(message string) {
	go log.Printf("[%s]: %s", l.serviceName, message)
}

func (l *Logger) Verbose(message string) {
	if l.verboseLevel {
		go log.Printf("[VERBOSE][%s]: %s", l.serviceName, message)
	}
}
