package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	files, err := filepath.Glob("internal/attest/testdata/vectors/*.preimage")
	if err != nil {
		log.Fatal(err)
	}
	for _, f := range files {
		content, err := os.ReadFile(f)
		if err != nil {
			log.Fatal(err)
		}
		lines := strings.Split(string(content), "\n")
		var newLines []string
		for _, line := range lines {
			if strings.HasPrefix(line, "evidence\t") && !strings.Contains(strings.Join(newLines, "\n"), "checks\t") {
				newLines = append(newLines, "checks\t")
			}
			if line == "" && len(newLines) > 0 && newLines[len(newLines)-1] != "checks\t" && !strings.Contains(strings.Join(newLines, "\n"), "checks\t") {
				newLines = append(newLines, "checks\t")
			}
			newLines = append(newLines, line)
		}
		// if no evidence and ends with newline, the last was empty string
		res := strings.Join(newLines, "\n")
		res = strings.ReplaceAll(res, "checks\t\n\n", "checks\t\n")
		if err := os.WriteFile(f, []byte(res), 0o644); err != nil {
			log.Fatal(err)
		}
		sum := sha256.Sum256([]byte(res))
		digest := hex.EncodeToString(sum[:])
		if err := os.WriteFile(strings.TrimSuffix(f, ".preimage")+".digest", []byte(digest+"\n"), 0o644); err != nil {
			log.Fatal(err)
		}
		fmt.Println("Updated", f, digest)
	}
}
