package main

import (
	"os/signal"
	"syscall"
	"context"
	"os/signal"
	"syscall"
	"context"
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/fatih/color"
)

type Secret struct {
	Type      string
	Pattern   string
	File      string
	Line      int
	Content   string
	Severity  string
}

var secretPatterns = map[string]*regexp.Regexp{
	"API_KEY":     regexp.MustCompile(`(?i)\b(api[_-]?key|apikey)\s*[=:]\s*['"]?([a-zA-Z0-9_\-]{20,})['"]?`),
	"SECRET_KEY":  regexp.MustCompile(`(?i)\b(secret[_-]?key|secretkey|private[_-]?key)\s*[=:]\s*['"]?([a-zA-Z0-9_\-]{20,})['"]?`),
	"PASSWORD":    regexp.MustCompile(`(?i)\b(password|passwd|pwd)\s*[=:]\s*['"]?([^\s'"']{6,})['"]?`),
	"TOKEN":       regexp.MustCompile(`(?i)\b(token|auth[_-]?token|access[_-]?token)\s*[=:]\s*['"]?([a-zA-Z0-9_\-\.]{20,})['"]?`),
	"AWS_KEY":     regexp.MustCompile(`(?i)AKIA[0-9A-Z]{16}`),
	"PRIVATE_KEY": regexp.MustCompile(`-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----`),
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println(color.CyanString("secretdetector - Local Secret Scanner"))
		fmt.Println()
		fmt.Println("Usage: secretdetector <directory>")
		os.Exit(1)
	}

	dir := os.Args[1]
	secret, err := scanDirectory(dir)
	if err != nil {
		color.Red("Error: %v", err)
		os.Exit(1)
	}

	displaySecrets(secret)
}

func scanDirectory(dir string) ([]Secret, error) {
	var secrets []Secret

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip binary files and common non-source files
		if info.IsDir() {
			skipDirs := []string{".git", "node_modules", "vendor", "bin", ".min.js"}
			for _, skip := range skipDirs {
				if info.Name() == skip {
					return filepath.SkipDir
				}
			}
			return nil
		}

		// Skip binary files
		if strings.HasSuffix(info.Name(), ".bin") || strings.HasSuffix(info.Name(), ".exe") {
			return nil
		}

		fileSecrets := scanFile(path)
		secrets = append(secrets, fileSecrets...)
		return nil
	})

	return secrets, err
}

func scanFile(filename string) []Secret {
	file, err := os.Open(filename)
	if err != nil {
		return nil
	}
	defer file.Close()

	var secrets []Secret
	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		for secretType, pattern := range secretPatterns {
			matches := pattern.FindAllStringSubmatch(line, -1)
			for _, match := range matches {
				severity := "WARNING"
				if secretType == "AWS_KEY" || secretType == "PRIVATE_KEY" {
					severity = "CRITICAL"
				}

				secrets = append(secrets, Secret{
					Type:     secretType,
					Pattern:  secretType,
					File:     filename,
					Line:     lineNum,
					Content:  match[0],
					Severity: severity,
				})
			}
		}
	}

	return secrets
}

func displaySecrets(secrets []Secret) {
	if len(secrets) == 0 {
		fmt.Println(color.GreenString("\nNo secrets found!"))
		return
	}

	fmt.Println(color.CyanString("\n=== SECRET SCAN RESULTS ===\n"))

	for _, s := range secrets {
		severityColor := color.YellowString
		if s.Severity == "CRITICAL" {
			severityColor = color.RedString
		}

		fmt.Printf("[%s] %s in %s:%d\n",
			severityColor(s.Severity),
			s.Type,
			color.HiWhiteString(s.File),
			s.Line,
		)

		// Mask the secret value
		masked := maskSecret(s.Content)
		fmt.Printf("  Found: %s\n\n", masked)
	}

	fmt.Printf("Total secrets found: %d\n", len(secrets))
}

func maskSecret(content string) string {
	if len(content) <= 8 {
		return strings.Repeat("*", len(content))
	}
	return content[:4] + strings.Repeat("*", len(content)-8) + content[len(content)-4:]
}