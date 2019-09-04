// Copyright 2019 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package auth

import (
	"context"
	"net/http"
	"reflect"
	"testing"
)

func TestSAMLProviderConfigInvalidID(t *testing.T) {
	client := &Client{
		providerConfigClient: &providerConfigClient{},
	}

	if _, err := client.SAMLProviderConfig(context.Background(), ""); err == nil {
		t.Errorf("SAMLProviderConfig('') = nil; want = error")
	}

	if _, err := client.SAMLProviderConfig(context.Background(), "foo"); err == nil {
		t.Errorf("SAMLProviderConfig('foo') = nil; want = error")
	}

	if _, err := client.SAMLProviderConfig(context.Background(), "oidc.foo"); err == nil {
		t.Errorf("SAMLProviderConfig('oidc.foo') = nil; want = error")
	}
}

func TestSAMLProviderConfigNoProjectID(t *testing.T) {
	client := &Client{
		providerConfigClient: &providerConfigClient{},
	}

	want := "project id not available"
	if _, err := client.SAMLProviderConfig(context.Background(), "saml.provider"); err == nil || err.Error() != want {
		t.Errorf("SAMLProviderConfig() = %v; want = %q", err, want)
	}
}

func TestSAMLProviderConfig(t *testing.T) {
	resp := `{
               "name":"projects/mock-project-id/inboundSamlConfigs/saml.provider",
                "idpConfig": {
                    "idpEntityId": "IDP_ENTITY_ID",
                    "ssoUrl": "https://example.com/login",
                    "signRequest": true,
                    "idpCertificates": [
                        {"x509Certificate": "CERT1"},
                        {"x509Certificate": "CERT2"}
                    ]
                },
                "spConfig": {
                    "spEntityId": "RP_ENTITY_ID",
                    "callbackUri": "https://projectId.firebaseapp.com/__/auth/handler"
                },
                "displayName": "samlProviderName",
                "enabled": true
        }`
	s := echoServer([]byte(resp), t)
	defer s.Close()

	saml, err := s.Client.SAMLProviderConfig(context.Background(), "saml.provider")
	if err != nil {
		t.Fatal(err)
	}

	want := &SAMLProviderConfig{
		ProviderConfig: &ProviderConfig{
			ID:          "saml.provider",
			DisplayName: "samlProviderName",
			Enabled:     true,
		},
		IDPEntityID:      "IDP_ENTITY_ID",
		SSOURL:           "https://example.com/login",
		X509Certificates: []string{"CERT1", "CERT2"},
		RPEntityID:       "RP_ENTITY_ID",
		CallbackURL:      "https://projectId.firebaseapp.com/__/auth/handler",
	}
	if !reflect.DeepEqual(saml, want) {
		t.Errorf("SAMLProviderConfig() = %#v; want = %#v", saml, want)
	}

	req := s.Req[0]
	if req.Method != http.MethodGet {
		t.Errorf("SAMLProviderConfig() Method = %q; want = %q", req.Method, http.MethodGet)
	}

	wantURL := "/projects/mock-project-id/inboundSamlConfigs/saml.provider"
	if req.URL.Path != wantURL {
		t.Errorf("SAMLProviderConfig() URL = %q; want = %q", req.URL.Path, wantURL)
	}
}

func TestSAMLProviderConfigMinimal(t *testing.T) {
	resp := `{
                "name":"projects/project_id/inboundSamlConfigs/saml.provider"
        }`
	s := echoServer([]byte(resp), t)
	defer s.Close()

	saml, err := s.Client.SAMLProviderConfig(context.Background(), "saml.provider")
	if err != nil {
		t.Fatal(err)
	}

	want := &SAMLProviderConfig{
		ProviderConfig: &ProviderConfig{
			ID: "saml.provider",
		},
	}
	if !reflect.DeepEqual(saml, want) {
		t.Errorf("SAMLProviderConfig() = %#v; want = %#v", saml, want)
	}
}
