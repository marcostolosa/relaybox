package executil

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

func RunCommand(cmdStr string) error {
	fmt.Println(strings.Split(cmdStr, " "))
	cmd := exec.Command(
		strings.Split(cmdStr, " ")[0],
		strings.Split(cmdStr, " ")[1:]...,
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func RunCommandPowershell(cmdStr string) error {
	cmd := exec.Command(
		"powershell",
		"-NoProfile",
		"-NonInteractive",
		"-Command",
		cmdStr,
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func RunCommandPowershellWithOutput(cmdStr string) (string, error) {
	cmd := exec.Command(
		"powershell",
		"-NoProfile",
		"-NonInteractive",
		"-Command",
		cmdStr,
	)

	stdoutReader, err := cmd.StdoutPipe()
	if err != nil {
		return "", err
	}

	if err := cmd.Start(); err != nil {
		return "", err
	}

	output, err := io.ReadAll(stdoutReader)
	if err != nil {
		return "", err
	}

	if err := cmd.Wait(); err != nil {
		return "", err
	}

	return string(output), nil
}
