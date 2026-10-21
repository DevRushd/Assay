package fixtures

import (
	"fmt"
	"strings"
)

// Unified renders the change from old to new for one file as a unified diff.
//
// It is computed here rather than shelled out to `diff`, so the tool has no
// external dependency and behaves the same on every platform. Fixture files are
// small, so the quadratic table below is not a concern.
func Unified(file string, old, new []byte) string {
	oldLines := splitLines(old)
	newLines := splitLines(new)

	var b strings.Builder
	fmt.Fprintf(&b, "--- a/%s\n", file)
	fmt.Fprintf(&b, "+++ b/%s\n", file)
	fmt.Fprintf(&b, "@@ -1,%d +1,%d @@\n", len(oldLines), len(newLines))
	for _, op := range diffOps(oldLines, newLines) {
		b.WriteString(op.prefix)
		b.WriteString(op.line)
		b.WriteByte('\n')
	}
	return b.String()
}

type diffOp struct {
	prefix string // " ", "-" or "+"
	line   string
}

func splitLines(b []byte) []string {
	if len(b) == 0 {
		return nil
	}
	return strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
}

// diffOps computes a longest-common-subsequence diff, so unchanged lines are
// shown once with a context marker rather than as a delete plus an add.
func diffOps(a, b []string) []diffOp {
	n, m := len(a), len(b)
	// lcs[i][j] is the length of the longest common subsequence of a[i:] and
	// b[j:], consulted only to choose between consuming from a or from b.
	lcs := make([][]int, n+1)
	for i := range lcs {
		lcs[i] = make([]int, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			switch {
			case a[i] == b[j]:
				lcs[i][j] = lcs[i+1][j+1] + 1
			case lcs[i+1][j] >= lcs[i][j+1]:
				lcs[i][j] = lcs[i+1][j]
			default:
				lcs[i][j] = lcs[i][j+1]
			}
		}
	}

	ops := make([]diffOp, 0, n+m)
	i, j := 0, 0
	for i < n && j < m {
		switch {
		case a[i] == b[j]:
			ops = append(ops, diffOp{" ", a[i]})
			i++
			j++
		case lcs[i+1][j] >= lcs[i][j+1]:
			ops = append(ops, diffOp{"-", a[i]})
			i++
		default:
			ops = append(ops, diffOp{"+", b[j]})
			j++
		}
	}
	for ; i < n; i++ {
		ops = append(ops, diffOp{"-", a[i]})
	}
	for ; j < m; j++ {
		ops = append(ops, diffOp{"+", b[j]})
	}
	return ops
}
