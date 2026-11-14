package main

import (
	"fmt"
	"os"
)

func main() {
	// The last argument, so that `zbx run <image> -- /usr/local/bin/hello --whoami` (the
	// entrypoint kept, the path its first argument) asks the same as `-- --whoami`.
	if len(os.Args) > 1 && os.Args[len(os.Args)-1] == "--whoami" {
		fmt.Println(os.Getuid())
		return
	}
	fmt.Println("hello from zigbox")
}
