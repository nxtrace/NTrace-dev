//go:build !windows

package cmd

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

func TestMTRJSONProcessSignals(t *testing.T) {
	for _, report := range []bool{false, true} {
		for _, data := range []string{"zero", "partial"} {
			for _, sig := range []os.Signal{os.Interrupt, syscall.SIGTERM} {
				ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
				args := []string{"-test.run=^TestMTRJSONCLIProcess$", "--", "--json", "--data-provider", "disable-geoip", "-s", "127.0.0.1", "127.0.0.1"}
				if enableTraceroute {
					args = append(args, "--mtr")
				}
				if report {
					args = append(args, "-r")
				}
				process := exec.CommandContext(ctx, os.Args[0], args...)
				process.Env = append(os.Environ(), "NTRACE_TEST_MTR_JSON_PROCESS=1", "NTRACE_TEST_MTR_JSON_BLOCK="+data)
				var stdout bytes.Buffer
				process.Stdout = &stdout
				stderr, err := process.StderrPipe()
				if err != nil {
					t.Fatal(err)
				}
				if err = process.Start(); err != nil {
					t.Fatal(err)
				}
				scanner := bufio.NewScanner(stderr)
				ready := false
				for scanner.Scan() {
					if scanner.Text() == "ready" {
						ready = true
						break
					}
				}
				if !ready {
					cancel()
					_ = process.Wait()
					t.Fatal("session never became ready")
				}
				if err = process.Process.Signal(sig); err != nil {
					t.Fatal(err)
				}
				err = process.Wait()
				cancel()
				wantCode, wantSignal := 130, `"SIGINT"`
				if sig == syscall.SIGTERM {
					wantCode, wantSignal = 143, `"SIGTERM"`
				}
				var exit *exec.ExitError
				if !errors.As(err, &exit) || exit.ExitCode() != wantCode {
					t.Fatalf("report=%v data=%s signal=%v: exit=%v stdout=%s", report, data, sig, err, stdout.String())
				}
				values := decodeMTRJSON(t, stdout.Bytes())
				end := values[len(values)-1]
				if string(end["end_reason"]) != `"interrupted"` || string(end["signal"]) != wantSignal {
					t.Fatalf("incorrect signal outcome: %s", stdout.String())
				}
				if report && (len(values) != 1 || (string(end["stats"]) == "[]") != (data == "zero")) {
					t.Fatalf("partial report: %s", stdout.String())
				}
				if !report && len(values) != map[string]int{"zero": 2, "partial": 3}[data] {
					t.Fatalf("partial stream: %s", stdout.String())
				}
			}
		}
	}
}
