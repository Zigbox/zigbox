package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "--whoami" {
		fmt.Println(os.Getuid())
		return
	}
	fmt.Println("hello from zigbox")
}
