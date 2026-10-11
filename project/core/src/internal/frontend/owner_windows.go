package frontend

import "os"

// The privileged job store is never installed or executed on Windows.
func ownedByProcess(info os.FileInfo) bool { return false }
