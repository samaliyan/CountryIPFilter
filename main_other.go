//go:build !windows

package main

import "fmt"

var Version = "dev"

func main() { fmt.Println("CountryIPFilter runs on Windows only.") }
