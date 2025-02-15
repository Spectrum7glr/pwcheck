//go:build windows
// +build windows

package pwcheck

import (
	"bufio"
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

// CheckDependencies for Windows ensures that WSL is installed and that qpdf and zipinfo are available in WSL.
// Office file checking remains optional.
func CheckDependencies() error {
	if _, err := exec.LookPath("wsl"); err != nil {
		return fmt.Errorf("WSL not found; please install WSL")
	}
	// Checkqpdf in WSL.
	cmd := exec.Command("wsl", "which", "qpdf")
	out, err := cmd.CombinedOutput()
	if err != nil || len(strings.TrimSpace(string(out))) == 0 {
		return fmt.Errorf("qpdf not found in WSL; please install qpdf in your WSL distribution")
	}
	// Check zipinfo in WSL.
	cmd = exec.Command("wsl", "which", "zipinfo")
	out, err = cmd.CombinedOutput()
	if err != nil || len(strings.TrimSpace(string(out))) == 0 {
		return fmt.Errorf("zipinfo not found in WSL; please install unzip in your WSL distribution")
	}
	// Do not fail if msoffcrypto-tool is missing; Office file checking is optional.
	return nil
}

// convertToLinuxPath converts a Windows path to a Linux path using wslpath.
func convertToLinuxPath(winPath string) (string, error) {
	wp := strings.Replace(winPath, `\`, `\\`, -1)

	cmd := exec.Command("wsl", "wslpath", wp)
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// CheckPDF uses WSL to run pdfinfo and returns true if the file appears encrypted.
func CheckPDF(file string) (bool, error) {
	linuxPath, err := convertToLinuxPath(file)
	if err != nil {
		return false, err
	}
	// fmt.Println("checking" + file)
	cmd := exec.Command("wsl", "qpdf", "--is-encrypted", linuxPath)
	_, err = cmd.Output()

	if err != nil {

		return false, nil
	}
	return true, nil
}

// CheckZIP uses WSL to run zipinfo -v and returns true if any line indicates encryption.
func CheckZIP(file string) (bool, error) {
	linuxPath, err := convertToLinuxPath(file)
	if err != nil {
		return false, err
	}
	// fmt.Println("checking" + file)
	cmd := exec.Command("wsl", "zipinfo", "-v", linuxPath)
	output, err := cmd.Output()
	if err != nil {
		return false, err
	}
	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(strings.ToLower(line), "file security status:") {
			if !strings.Contains(strings.ToLower(line), "not") {
				return true, nil
			}
			break
		}
	}
	return false, nil
}

// CheckOffice uses WSL to run msoffcrypto-tool for Office files.
// If msoffcrypto-tool is not found in WSL, it sets a warning flag and returns false.
func CheckOffice(file string) (bool, error) {

	linuxPath, err := convertToLinuxPath(file)
	if err != nil {
		return false, err
	}
	// fmt.Println("checking" + file)
	// Check for msoffcrypto-tool in WSL.
	cmd := exec.Command("wsl", "bash", "-l", "-c", "which msoffcrypto-tool")
	out, err := cmd.CombinedOutput()
	if err != nil || len(strings.TrimSpace(string(out))) == 0 {
		officeCheckWarning = true
		return false, nil
	}
	// Run msoffcrypto-tool in WSL using /dev/null as output.
	cmd = exec.Command("wsl", "bash", "-l", "-c", fmt.Sprintf("msoffcrypto-tool '%s' -t -v", linuxPath))
	output, err := cmd.CombinedOutput()
	if !strings.Contains(strings.ToLower(string(output)), "not encrypted") && strings.Contains(strings.ToLower(string(output)), "encrypted") {
		// fmt.Println("Gigi", strings.ToLower(string(output)))
		return true, nil
	}
	return false, nil
}
