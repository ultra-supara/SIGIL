// Command capabilities exists only for its function names (PR-4c-3a): it is built, never run.
package main

import (
	"net"
	"os"
	"os/exec"
)

func main() {
	_ = exec.Command("true").Run()
	if c, err := net.Dial("tcp", "127.0.0.1:1"); err == nil {
		c.Close()
	}
	if f, err := os.Create("/tmp/sigil-capabilities"); err == nil {
		f.Close()
	}
	if f, err := os.Open("/tmp/sigil-capabilities"); err == nil {
		f.Close()
	}
	os.Exit(recorded())
}

// recorded's code is recorded under a file named like a mapped function (PR-4c-3a plan review
// P2): that name is in .gopclntab's file table, not in its function-name table, and gives no hint.
// main calls it because the linker drops an unreachable function, and its file name with it.
//
//line syscall.Exec:1
func recorded() int { return len(os.Args) - 1 }
