//go:build linux || darwin
// +build linux darwin

package pwcheck

import (
	"bufio"
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

// CheckDependencies ensures that qpdf and zipinfo are installed on Linux.
// (Office file checking is optional.)
func CheckDependencies() error {
	if _, err := exec.LookPath("qpdf"); err != nil {
		return fmt.Errorf("qpdf not found; please install qpdf")
	}
	if _, err := exec.LookPath("zipinfo"); err != nil {
		return fmt.Errorf("zipinfo not found; please install unzip")
	}
	// Do not fail if msoffcrypto-tool is missing; Office file checking is optional.
	return nil
}

func CheckDependenciesOffice() bool {
	if _, err := exec.LookPath("msoffcrypto-tool"); err != nil {
		return false
	}
	return true
}

// CheckPDF runs qpdf on the file and returns true if it appears encrypted.
func CheckPDF(file string) (bool, error) {
	cmd := exec.Command("qpdf", "--is-encrypted", file)
	_, err := cmd.Output()

	if err != nil {

		return false, nil
	}
	return true, nil
}

// CheckZIP runs zipinfo -v on the file and returns true if any output indicates encryption.
func CheckZIP(file string) (bool, error) {
	cmd := exec.Command("zipinfo", "-v", file)
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

// CheckOffice uses msoffcrypto-tool to determine if an Office file is password-protected.
// If msoffcrypto-tool is not installed, it sets a warning flag and returns false.
func CheckOffice(file string) (bool, error) {

	// Run msoffcrypto-tool with /dev/null as output.
	cmd := exec.Command("msoffcrypto-tool", file, "-t", "-v")
	output, _ := cmd.CombinedOutput()
	if !strings.Contains(strings.ToLower(string(output)), "not encrypted") {
		// fmt.Println("Gigi")
		return true, nil
	}
	return false, nil
	// fmt.Errorf("msoffcrypto-tool error: %s", string(output))

}
