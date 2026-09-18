/*
Copyright 2026 the kube-rbac-proxy maintainers. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package app

import (
	cryptotls "crypto/tls"
	"reflect"
	"testing"

	"github.com/brancz/kube-rbac-proxy/cmd/kube-rbac-proxy/app/options"
)

func TestApplyTLSConfigFromFlags(t *testing.T) {
	proxyOptions := options.NewProxyRunOptions()
	flagSets := proxyOptions.Flags()
	flagSet := flagSets.FlagSet("kube-rbac-proxy")
	if err := flagSet.Parse([]string{"--tls-curve-preferences=23,4588"}); err != nil {
		t.Fatalf("parsing flags: %v", err)
	}

	config := &cryptotls.Config{}
	if err := applyTLSConfig(config, proxyOptions.TLS); err != nil {
		t.Fatalf("applyTLSConfig() returned an error: %v", err)
	}

	for _, want := range []cryptotls.CurveID{cryptotls.CurveP256, cryptotls.X25519MLKEM768} {
		found := false
		for _, got := range config.CurvePreferences {
			if got == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("curve %v is missing from %v", want, config.CurvePreferences)
		}
	}
	if config.MinVersion != cryptotls.VersionTLS12 {
		t.Errorf("MinVersion = %d, want %d", config.MinVersion, cryptotls.VersionTLS12)
	}
}

func TestApplyTLSConfigSetsMinVersionAndCipherSuites(t *testing.T) {
	tests := []struct {
		name        string
		minVersion  string
		ciphers     []string
		wantMin     uint16
		wantCiphers []uint16
	}{
		{
			name:        "short TLS 1.2 name",
			minVersion:  "TLS1.2",
			ciphers:     []string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
			wantMin:     cryptotls.VersionTLS12,
			wantCiphers: []uint16{cryptotls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		},
		{
			name:        "Go TLS 1.3 name",
			minVersion:  "VersionTLS13",
			ciphers:     []string{"TLS_AES_128_GCM_SHA256"},
			wantMin:     cryptotls.VersionTLS13,
			wantCiphers: []uint16{cryptotls.TLS_AES_128_GCM_SHA256},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &cryptotls.Config{}
			if err := applyTLSConfig(config, &options.TLSConfig{
				MinVersion:   tt.minVersion,
				CipherSuites: tt.ciphers,
			}); err != nil {
				t.Fatalf("applyTLSConfig() returned an error: %v", err)
			}
			if config.MinVersion != tt.wantMin {
				t.Errorf("MinVersion = %d, want %d", config.MinVersion, tt.wantMin)
			}
			if !reflect.DeepEqual(config.CipherSuites, tt.wantCiphers) {
				t.Errorf("CipherSuites = %v, want %v", config.CipherSuites, tt.wantCiphers)
			}
		})
	}
}

func TestApplyTLSConfigRejectsUnsupportedTLSValues(t *testing.T) {
	tests := []struct {
		name    string
		options *options.TLSConfig
	}{
		{
			name:    "unsupported minimum version",
			options: &options.TLSConfig{MinVersion: "VersionTLS99"},
		},
		{
			name:    "unsupported cipher suite",
			options: &options.TLSConfig{MinVersion: "VersionTLS12", CipherSuites: []string{"NOT_A_CIPHER"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := applyTLSConfig(&cryptotls.Config{}, tt.options); err == nil {
				t.Fatal("applyTLSConfig() returned no error")
			}
		})
	}
}

func TestApplyTLSConfigLeavesCipherDefaultsWhenUnset(t *testing.T) {
	config := &cryptotls.Config{}
	if err := applyTLSConfig(config, &options.TLSConfig{MinVersion: "VersionTLS12"}); err != nil {
		t.Fatalf("applyTLSConfig() returned an error: %v", err)
	}
	if config.CipherSuites != nil {
		t.Fatalf("CipherSuites = %v, want nil so Go defaults remain active", config.CipherSuites)
	}
}

func TestNormalizeTLSVersion(t *testing.T) {
	tests := map[string]string{
		"TLS1.2":       "VersionTLS12",
		"TLS1.3":       "VersionTLS13",
		"VersionTLS12": "VersionTLS12",
		"unsupported":  "unsupported",
	}
	for input, want := range tests {
		if got := normalizeTLSVersion(input); got != want {
			t.Errorf("normalizeTLSVersion(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestApplyTLSConfigRejectsUnsupportedCurveID(t *testing.T) {
	config := &cryptotls.Config{}
	if err := applyTLSConfig(config, &options.TLSConfig{MinVersion: "VersionTLS12", CurvePreferences: []int32{65535}}); err == nil {
		t.Fatal("expected unsupported CurveID to return an error")
	}
}
