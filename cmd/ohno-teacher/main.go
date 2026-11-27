package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/welkin-moon/ohno/teacher"
)

// Version is set at build time via -ldflags "-X main.Version=...".
var Version = "dev"

func main() {
	if len(os.Args) == 1 {
		if err := teacher.EasyStart(); err != nil {
			fmt.Fprintln(os.Stderr, "ohno-teacher:", err)
			os.Exit(1)
		}
		return
	}

	fs := flag.NewFlagSet("ohno-teacher", flag.ExitOnError)
	statePath := fs.String("state", "", "Path to private writable state file")
	controlPort := fs.Int("control-port", 8765, "Loopback-only teacher UI port")
	initState := fs.Bool("init", false, "Create empty teacher state")
	genCert := fs.Bool("generate-certificate", false, "Generate a local HTTPS certificate")
	host := fs.String("host", "", "Hostname or IP for certificate")
	certPath := fs.String("cert", "", "PEM certificate")
	keyPath := fs.String("key", "", "PEM private key")
	bind := fs.String("bind", "127.0.0.1", "API bind address")
	port := fs.Int("port", 8443, "Student HTTPS API port")
	traceUpdates := fs.Bool("trace-update-http", false, "Print public update route/status diagnostics")
	showVersion := fs.Bool("version", false, "Print version and exit")
	_ = fs.Parse(os.Args[1:])

	if *showVersion {
		fmt.Println("ohno-teacher", Version)
		return
	}
	if *genCert {
		if *certPath == "" || *keyPath == "" || *host == "" {
			fmt.Fprintln(os.Stderr, "--cert, --key and --host are required")
			os.Exit(2)
		}
		if err := teacher.CreateCertificate(*certPath, *keyPath, *host); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println("Certificate created. Protect the private key and install the certificate only on managed devices.")
		return
	}
	if *statePath == "" {
		fmt.Fprintln(os.Stderr, "--state is required")
		os.Exit(2)
	}
	if *initState {
		st, err := teacher.InitializeStore(*statePath)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		st.Close()
		fmt.Println("State initialized. Teacher management is loopback-only and has no login password.")
		return
	}
	if *certPath == "" || *keyPath == "" {
		fmt.Fprintln(os.Stderr, "HTTPS certificate and private key are required")
		os.Exit(2)
	}
	err := teacher.ServeTeacher(teacher.ServeOptions{
		StatePath:       *statePath,
		CertPath:        *certPath,
		KeyPath:         *keyPath,
		Bind:            *bind,
		Port:            *port,
		ControlPort:     *controlPort,
		EnrollmentHost:  *host,
		TraceUpdateHTTP: *traceUpdates,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
