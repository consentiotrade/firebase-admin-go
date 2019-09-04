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
	"errors"
	"fmt"
	"net/http"
	"strings"

	"firebase.google.com/go/internal"
)

const providerConfigEndpoint = "https://identitytoolkit.googleapis.com/v2beta1"

// ProviderConfig is the base configuration common to all auth providers.
type ProviderConfig struct {
	ID          string
	DisplayName string
	Enabled     bool
}

// SAMLProviderConfig represents a SAML auth provider configuration.
//
// See http://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-tech-overview-2.0.html
type SAMLProviderConfig struct {
	*ProviderConfig
	IDPEntityID      string
	SSOURL           string
	X509Certificates []string
	RPEntityID       string
	CallbackURL      string
}

type providerConfigClient struct {
	providerConfigEndpoint string
	projectID              string
	httpClient             *internal.HTTPClient
}

func newProviderConfigClient(hc *http.Client, conf *internal.AuthConfig) *providerConfigClient {
	client := &internal.HTTPClient{
		Client:    hc,
		SuccessFn: internal.HasSuccessStatus,
		Opts: []internal.HTTPOption{
			internal.WithHeader("X-Client-Version", fmt.Sprintf("Go/Admin/%s", conf.Version)),
		},
	}
	return &providerConfigClient{
		providerConfigEndpoint: providerConfigEndpoint,
		projectID:              conf.ProjectID,
		httpClient:             client,
	}
}

// SAMLProviderConfig looks up the SAML provider configuration with given ID.
func (c *providerConfigClient) SAMLProviderConfig(ctx context.Context, id string) (*SAMLProviderConfig, error) {
	if !strings.HasPrefix(id, "saml.") {
		return nil, fmt.Errorf("invalid SAML provider config id: %q", id)
	}

	url, err := c.makeProviderConfigURL(fmt.Sprintf("/inboundSamlConfigs/%s", id))
	if err != nil {
		return nil, err
	}

	req := &internal.Request{
		Method: http.MethodGet,
		URL:    url,
	}
	var result struct {
		Name      string `json:"name"`
		IDPConfig struct {
			IDPEntityID     string `json:"idpEntityId"`
			SSOURL          string `json:"ssoUrl"`
			IDPCertificates []struct {
				X509Certificate string `json:"x509Certificate"`
			} `json:"idpCertificates"`
			SignRequest bool `json:"signRequest"`
		}
		SPConfig struct {
			SPEntityID  string `json:"spEntityId"`
			CallbackURI string `json:"callbackUri"`
		} `json:"spConfig"`
		DisplayName string `json:"displayName"`
		Enabled     bool   `json:"enabled"`
	}
	_, err = c.httpClient.DoAndUnmarshal(ctx, req, &result)
	if err != nil {
		return nil, err
	}

	var certs []string
	for _, cert := range result.IDPConfig.IDPCertificates {
		certs = append(certs, cert.X509Certificate)
	}
	return &SAMLProviderConfig{
		ProviderConfig: &ProviderConfig{
			ID:          extractResourceID(result.Name),
			DisplayName: result.DisplayName,
			Enabled:     result.Enabled,
		},
		IDPEntityID:      result.IDPConfig.IDPEntityID,
		SSOURL:           result.IDPConfig.SSOURL,
		X509Certificates: certs,
		RPEntityID:       result.SPConfig.SPEntityID,
		CallbackURL:      result.SPConfig.CallbackURI,
	}, nil
}

func (c *providerConfigClient) makeProviderConfigURL(path string) (string, error) {
	if c.projectID == "" {
		return "", errors.New("project id not available")
	}

	url := fmt.Sprintf("%s/projects/%s%s", c.providerConfigEndpoint, c.projectID, path)
	return url, nil
}

func extractResourceID(name string) string {
	segments := strings.Split(name, "/")
	return segments[len(segments)-1]
}
