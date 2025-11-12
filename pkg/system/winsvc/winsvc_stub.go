//go:build !windows

package winsvc

import "fmt"

func platformErr() error {
	return fmt.Errorf("winsvc: Windows Service APIs are only supported on Windows")
}

func Disable(string) error { return platformErr() }
func Enable(string) error  { return platformErr() }
func Stop(string) error    { return platformErr() }
func Start(string) error   { return platformErr() }
