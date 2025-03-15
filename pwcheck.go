package pwcheck

import (
	"archive/zip"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu"
)

const (
	// Bit 0 mask (traditional encryption)
	bitEncryption = 1 << 0
	// Bit 6 mask (strong encryption)
	bitStrongEncryption = 1 << 6
)

// officeCheckWarning is set to true if any Office file was encountered but could not be checked.
var officeCheckWarning bool

// ExecuteCLI is the CLI entry point for the passwordprotection package.
// It parses command-line arguments and traverses each provided path (or the current directory if none are provided).
// After traversal, if any Office file could not be checked due to a missing external tool,
// a warning is printed with instructions.
func ExecuteCLI() {
	flag.Parse()
	paths := flag.Args()
	if len(paths) == 0 {
		paths = []string{"."}
	}

	// if err := CheckDependencies(); err != nil {
	// 	log.Fatalf("Dependency check failed: %v", err)
	// }

	office := CheckDependenciesOffice()

	for _, p := range paths {
		if err := TraversePath(p, office); err != nil {
			log.Printf("Error traversing %s: %v", p, err)
		}
	}

	// If any Office file was encountered and could not be checked, print a warning.
	if officeCheckWarning {
		fmt.Fprintln(os.Stderr, "Warning: Some Office files (e.g., DOCX, XLSX, PPTX) were detected but could not be checked for password protection because msoffcrypto-tool is not installed.")
		fmt.Fprintln(os.Stderr, "To enable checking of Office files, please install msoffcrypto-tool:")
		fmt.Fprintln(os.Stderr, "    pip install msoffcrypto-tool")
	}
}

// TraversePath recursively walks the given basePath and, for each PDF, ZIP, or Office file found,
// prints its path relative to basePath if it is detected as password‑protected.
func TraversePath(basePath string, office bool) error {
	absBase, err := filepath.Abs(basePath)
	if err != nil {
		return fmt.Errorf("error resolving base path: %v", err)
	}

	return filepath.Walk(absBase, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			log.Printf("Error accessing %s: %v", path, err)
			return nil
		}
		if info.IsDir() {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		var protected bool
		switch ext {
		case ".pdf":
			protected, err = CheckPDFGo(path)
		case ".zip":
			protected, err = CheckZIPGo(path)
		case ".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm", ".xls", ".doc":
			if office {

				protected, err = CheckOffice(path)

			} else {
				if !officeCheckWarning {
					officeCheckWarning = true
				}
				return nil
			}

		default:
			return nil
		}
		if err != nil {
			log.Printf("Error checking %s: %v", path, err)
			return nil
		}
		if protected {
			rel, err := filepath.Rel(absBase, path)
			if err != nil {
				fmt.Println(path)
			} else {
				fmt.Println(rel)
			}
		}
		return nil
	})
}

func CheckPDFGo(file string) (bool, error) {
	_, err := api.ReadContextFile(file)
	if err != nil && errors.Is(err, pdfcpu.ErrWrongPassword) {
		return true, nil
	}

	return false, nil

}

func CheckZIPGo(zipPath string) (bool, error) {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return false, err
	}
	defer r.Close()

	// Check each file inside the ZIP
	for _, f := range r.File {
		// If the low bit of Flags is set, the file is encrypted
		if isEncrypted(f.Flags) {
			return true, nil
		}
	}
	return false, nil
}

func isEncrypted(flags uint16) bool {
	return (flags&bitEncryption) != 0 || (flags&bitStrongEncryption) != 0
}
