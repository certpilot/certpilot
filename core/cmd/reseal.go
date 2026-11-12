package main

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/certpilot/certpilot/core/engine/rekey"
	"github.com/certpilot/certpilot/core/server"
	"github.com/certpilot/certpilot/pkg/config"
)

// runReseal backs `--reseal`. It fails when anything is still sealed by a key
// other than the primary, so a script that goes on to drop the retired key
// stops here instead.
func runReseal(ctx context.Context, cfg *config.CoreConfig, dbConnStr string) error {
	result, report, err := server.Reseal(ctx, cfg, dbConnStr)
	if result != nil {
		fmt.Printf("re-sealed %d record(s) under key %s\n", result.Resealed, primaryOf(report))
		for _, kind := range sortedKeys(result.ByKind) {
			fmt.Printf("  %-22s %d\n", kind, result.ByKind[kind])
		}
		if result.ChangedMeanwhile > 0 {
			fmt.Printf("  %d record(s) were rewritten by the running core meanwhile and left as it wrote them\n",
				result.ChangedMeanwhile)
		}
		if result.Unreadable > 0 {
			fmt.Printf("  %d record(s) could not be opened and were left as they are; the log names each\n",
				result.Unreadable)
		}
	}
	if err != nil {
		return err
	}

	fmt.Println()
	printKeyReport(report)

	if result.Remaining > 0 {
		return fmt.Errorf("%d record(s) are still sealed by a key other than the primary. "+
			"Run --reseal again; do not drop a retired key until this reads zero", result.Remaining)
	}
	return nil
}

func printKeyReport(report *rekey.Report) {
	for _, k := range report.Keys {
		fmt.Printf("key %s (%s): %d sealed record(s)", k.KeyID, k.Status, k.SealedTotal)
		if k.Audit != nil {
			fmt.Printf(", signed audit entries %d to %d (%d)", k.Audit.FirstSeq, k.Audit.LastSeq, k.Audit.Entries)
		}
		fmt.Println()
		for _, kind := range sortedKeys(k.Sealed) {
			fmt.Printf("  %-22s %d\n", kind, k.Sealed[kind])
		}
	}
	if len(report.NotSealed) > 0 {
		var parts []string
		for _, kind := range sortedKeys(report.NotSealed) {
			parts = append(parts, fmt.Sprintf("%s %d", kind, report.NotSealed[kind]))
		}
		fmt.Fprintf(os.Stderr, "not sealed at all (written before sealing existed): %s\n", strings.Join(parts, ", "))
	}
}

func primaryOf(report *rekey.Report) string {
	if report == nil {
		return "(primary)"
	}
	return report.PrimaryKeyID
}

func sortedKeys(m map[string]int64) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
