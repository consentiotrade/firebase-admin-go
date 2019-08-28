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
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"firebase.google.com/go/internal"
)

// TenantClient provides APIs for managing users and verifying tokens associated with a specific tenant.
type TenantClient struct {
	tenantID string
}

// TenantID returns the ID of the tenant associated with this client.
func (tc *TenantClient) TenantID() string {
	return tc.tenantID
}

// Tenant represents a Firebase Auth tenant.
type Tenant struct {
	ID                    string `json:"name"`
	DisplayName           string `json:"displayName"`
	AllowPasswordSignUp   bool   `json:"allowPasswordSignup"`
	EnableEmailLinkSignIn bool   `json:"enableEmailLinkSignin"`
}

const idToolkitV2Beta1Endpoint = "https://identitytoolkit.googleapis.com/v2beta1"

// TenantManager provides APIs for managing Firebase Auth tenants in a project.
type TenantManager struct {
	baseURL    string
	projectID  string
	version    string
	httpClient *internal.HTTPClient
}

// AuthForTenant creates a new TenantClient for managing users and verifying tokens for a single tenant.
func (tm *TenantManager) AuthForTenant(tenantID string) (*TenantClient, error) {
	if tenantID == "" {
		return nil, errors.New("tenant id must not be empty")
	}

	return &TenantClient{tenantID}, nil
}

// Tenant returns the tenant identified by the provided tenant ID.
func (tm *TenantManager) Tenant(ctx context.Context, tenantID string) (*Tenant, error) {
	if tenantID == "" {
		return nil, errors.New("tenant id must not be empty")
	}

	path := fmt.Sprintf("/tenants/%s", tenantID)
	var tenant Tenant
	if err := tm.makeRequest(ctx, http.MethodGet, path, &tenant); err != nil {
		return nil, err
	}

	tenant.ID = extractResourceID(tenant.ID)
	return &tenant, nil
}

func (tm *TenantManager) makeRequest(
	ctx context.Context, method, path string, parsed interface{}) error {
	if tm.projectID == "" {
		return errors.New("project id not available")
	}

	versionHeader := internal.WithHeader("X-Client-Version", tm.version)
	req := &internal.Request{
		Method: method,
		URL:    fmt.Sprintf("%s/projects/%s%s", tm.baseURL, tm.projectID, path),
		Opts:   []internal.HTTPOption{versionHeader},
	}

	resp, err := tm.httpClient.Do(ctx, req)
	if err != nil {
		return err
	}

	if resp.Status != http.StatusOK {
		return handlePlatformError(resp)
	}

	return json.Unmarshal(resp.Body, &parsed)
}

func extractResourceID(resourceName string) string {
	segments := strings.Split(resourceName, "/")
	return segments[len(segments)-1]
}

func handlePlatformError(resp *internal.Response) error {
	var httpErr struct {
		Error struct {
			Status  string `json:"status"`
			Message string `json:"message"`
		} `json:"error"`
	}
	json.Unmarshal(resp.Body, &httpErr) // ignore any json parse errors at this level
	serverCode := httpErr.Error.Status
	return internal.Errorf(serverCode, httpErr.Error.Message)
}
