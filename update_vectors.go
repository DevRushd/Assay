package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"path/filepath"
)

func main() {
	files, _ := filepath.Glob("internal/attest/testdata/vectors/*.preimage")
	for _, f := range files {
		content, _ := os.ReadFile(f)
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
        res = strings.Replace(res, "checks\t\n\n", "checks\t\n", -1)
		os.WriteFile(f, []byte(res), 0644)
		sum := sha256.Sum256([]byte(res))
		digest := hex.EncodeToString(sum[:])
		os.WriteFile(strings.TrimSuffix(f, ".preimage")+".digest", []byte(digest+"\n"), 0644)
		fmt.Println("Updated", f, digest)
	}
}
