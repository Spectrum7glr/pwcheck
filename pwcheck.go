package pwcheck

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
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

	if err := CheckDependencies(); err != nil {
		log.Fatalf("Dependency check failed: %v", err)
	}

	for _, p := range paths {
		if err := TraversePath(p); err != nil {
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
func TraversePath(basePath string) error {
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
			protected, err = CheckPDF(path)
		case ".zip":
			protected, err = CheckZIP(path)
		case ".docx", ".xlsx", ".pptx":
			protected, err = CheckOffice(path)
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
