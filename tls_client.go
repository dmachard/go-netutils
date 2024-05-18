package netutils

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

const (
	TLSV10 = "1.0"
	TLSV11 = "1.1"
	TLSV12 = "1.2"
	TLSV13 = "1.3"
)

var (
	TLSVersion = map[string]uint16{
		TLSV10: tls.VersionTLS10,
		TLSV11: tls.VersionTLS11,
		TLSV12: tls.VersionTLS12,
		TLSV13: tls.VersionTLS13,
	}
)

var clientCipherSuites = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
}

func IsValidTLS(mode string) bool {
	switch mode {
	case
		TLSV10,
		TLSV11,
		TLSV12,
		TLSV13:
		return true
	}
	return false
}

type TLSOptions struct {
	CAFile             string
	CertFile           string
	KeyFile            string
	InsecureSkipVerify bool
	MinVersion         string
}

func TLSClientConfig(options TLSOptions) (*tls.Config, error) {

	tlsConfig := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: false,
		CipherSuites:       clientCipherSuites,
	}
	tlsConfig.InsecureSkipVerify = options.InsecureSkipVerify

	if len(options.CAFile) > 0 {
		CAs := x509.NewCertPool()
		pemData, err := os.ReadFile(options.CAFile)
		if err != nil {
			return nil, fmt.Errorf("could not read CA certificate %q: %w", options.CAFile, err)
		}
		if !CAs.AppendCertsFromPEM(pemData) {
			return nil, fmt.Errorf("failed to append certificates from PEM file: %q", options.CAFile)
		}
		tlsConfig.RootCAs = CAs
	}

	if len(options.CertFile) > 0 && len(options.KeyFile) > 0 {
		cer, err := tls.LoadX509KeyPair(options.CertFile, options.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("loading certificate failed: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cer}
	}

	if tlsVersion, ok := TLSVersion[options.MinVersion]; ok {
		tlsConfig.MinVersion = tlsVersion
	} else {
		return nil, fmt.Errorf("invalid minimum TLS version: %x", options.MinVersion)
	}

	return tlsConfig, nil
}
