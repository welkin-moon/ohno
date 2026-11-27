package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/welkin-moon/ohno/teacher"
)

func main() {
	fs := flag.NewFlagSet("ohno-pkg", flag.ExitOnError)
	version := fs.String("version", "", "Release version (e.g. 1.0.0)")
	directory := fs.String("directory", "", "Directory containing the 6 fixed x64 payload files")
	output := fs.String("output", "", "Output .ohno file path (must not already exist)")
	_ = fs.Parse(os.Args[1:])

	if *version == "" || *directory == "" || *output == "" {
		fmt.Fprintln(os.Stderr, "Usage: ohno-pkg --version VERSION --directory DIR --output FILE")
		os.Exit(2)
	}
	files := make(map[string][]byte, len(teacher.PackageFiles))
	for _, name := range teacher.PackageFiles {
		data, err := os.ReadFile(filepath.Join(*directory, name))
		if err != nil {
			fmt.Fprintf(os.Stderr, "cannot read %s: %v\n", name, err)
			os.Exit(1)
		}
		files[name] = data
	}
	pkg, err := teacher.BuildPackage(*version, files)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid package: %v\n", err)
		os.Exit(1)
	}
	f, err := os.OpenFile(*output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot create output %s: %v\n", *output, err)
		os.Exit(1)
	}
	if _, err := f.Write(pkg); err != nil {
		f.Close()
		_ = os.Remove(*output)
		fmt.Fprintf(os.Stderr, "write failed: %v\n", err)
		os.Exit(1)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(*output)
		fmt.Fprintf(os.Stderr, "close failed: %v\n", err)
		os.Exit(1)
	}
}
