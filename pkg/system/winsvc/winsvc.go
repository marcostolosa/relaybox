//go:build windows

package winsvc

import (
	"fmt"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

func Disable(name string) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("could not connect to SCM: %v", err)
	}
	defer m.Disconnect()

	svcHandle, err := m.OpenService(name)
	if err != nil {
		return fmt.Errorf("service %q not found: %v", name, err)
	}
	defer svcHandle.Close()

	cfg, err := svcHandle.Config()
	if err == nil {
		cfg.StartType = mgr.StartDisabled
		err = svcHandle.UpdateConfig(cfg)
	}
	return err
}

func Enable(name string) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("could not connect to SCM: %v", err)
	}
	defer m.Disconnect()

	svcHandle, err := m.OpenService(name)
	if err != nil {
		return fmt.Errorf("service %q not found: %v", name, err)
	}
	defer svcHandle.Close()

	cfg, err := svcHandle.Config()
	if err == nil {
		cfg.StartType = mgr.StartAutomatic
		err = svcHandle.UpdateConfig(cfg)
	}
	return err
}

func Stop(name string) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("could not connect to SCM: %v", err)
	}
	defer m.Disconnect()

	svcHandle, err := m.OpenService(name)
	if err != nil {
		return fmt.Errorf("service %q not found: %v", name, err)
	}
	defer svcHandle.Close()

	_, err = svcHandle.Control(svc.Stop)
	if err != nil {
		return fmt.Errorf("failed to stop service %q: %v", name, err)
	}
	return nil
}

func Start(name string) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("could not connect to SCM: %v", err)
	}
	defer m.Disconnect()

	svcHandle, err := m.OpenService(name)
	if err != nil {
		return fmt.Errorf("service %q not found: %v", name, err)
	}
	defer svcHandle.Close()

	if err := svcHandle.Start(); err != nil {
		return fmt.Errorf("failed to start service %q: %v", name, err)
	}

	return nil
}
