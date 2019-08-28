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

	"firebase.google.com/go/internal"
)

func TestAuthForTenantEmptyTenantID(t *testing.T) {
	tm := &TenantManager{}
	tc, err := tm.AuthForTenant("")
	if tc != nil || err == nil {
		t.Errorf("AuthForTenant() = (%v, %v); want = (nil, error)", tc, err)
	}
}

func TestAuthForTenant(t *testing.T) {
	tm := &TenantManager{}
	tc, err := tm.AuthForTenant("my-tenant")
	if err != nil {
		t.Fatal(err)
	}

	tid := tc.TenantID()
	if tid != "my-tenant" {
		t.Errorf("TenantID() = %q; want = %q", tid, "my-tenant")
	}
}

func TestTenantEmptyTenantID(t *testing.T) {
	tm := &TenantManager{}
	tc, err := tm.Tenant(context.Background(), "")
	if tc != nil || err == nil {
		t.Errorf("Tenant() = (%v, %v); want = (nil, error)", tc, err)
	}
}

func TestTenant(t *testing.T) {
	resp := `{
		"name": "projects/mock-project-id/tenant/my-tenant",
		"displayName": "My Tenant"
	}`
	s := echoServer([]byte(resp), t)
	defer s.Close()

	tm := s.Client.TenantManager
	tenant, err := tm.Tenant(context.Background(), "my-tenant")
	if err != nil {
		t.Fatal(err)
	}

	want := &Tenant{
		ID:          "my-tenant",
		DisplayName: "My Tenant",
	}
	if !reflect.DeepEqual(tenant, want) {
		t.Errorf("Tenant() = %#v; want = %#v", tenant, want)
	}

	wantURL := "/projects/mock-project-id/tenants/my-tenant"
	if s.Req[0].URL.Path != wantURL {
		t.Errorf("Tenant() URL = %q; want = %q", s.Req[0].URL.Path, wantURL)
	}
}

func TestTenantWithEmailSignInConfig(t *testing.T) {
	resp := `{
		"name": "projects/mock-project-id/tenant/my-tenant",
		"displayName": "My Tenant",
		"allowPasswordSignup": true,
		"enableEmailLinkSignin": true
	}`
	s := echoServer([]byte(resp), t)
	defer s.Close()

	tm := s.Client.TenantManager
	tenant, err := tm.Tenant(context.Background(), "my-tenant")
	if err != nil {
		t.Fatal(err)
	}

	want := &Tenant{
		ID:                    "my-tenant",
		DisplayName:           "My Tenant",
		AllowPasswordSignUp:   true,
		EnableEmailLinkSignIn: true,
	}
	if !reflect.DeepEqual(tenant, want) {
		t.Errorf("Tenant() = %#v; want = %#v", tenant, want)
	}

	wantURL := "/projects/mock-project-id/tenants/my-tenant"
	if s.Req[0].URL.Path != wantURL {
		t.Errorf("Tenant() URL = %q; want = %q", s.Req[0].URL.Path, wantURL)
	}
}

func TestTenantNotFoundError(t *testing.T) {
	resp := `{
		"error": {
			"status": "NOT_FOUND",
			"message": "Requested resource not found"
		}
	}`
	s := echoServer([]byte(resp), t)
	defer s.Close()
	s.Status = http.StatusNotFound
	want := "Requested resource not found"

	tm := s.Client.TenantManager
	tenant, err := tm.Tenant(context.Background(), "my-tenant")
	if tenant != nil || err == nil || err.Error() != want {
		t.Errorf("Tenant() = (%v, %v); want = (nil, %q)", tenant, err, want)
	}

	if !internal.HasErrorCode(err, "NOT_FOUND") {
		fe := err.(*internal.FirebaseError)
		t.Errorf("ErrorCode = %q; want = %q", fe.Code, "NOT_FOUND")
	}
}

func TestTenantManagerEmptyProjectID(t *testing.T) {
	tm := &TenantManager{}
	tc, err := tm.Tenant(context.Background(), "my-tenant")
	if tc != nil || err == nil {
		t.Errorf("Tenant() = (%v, %v); want = (nil, error)", tc, err)
	}
}

func TestTenantManagerTransportError(t *testing.T) {
	s := echoServer([]byte(`{}`), t)
	s.Close()

	tm := s.Client.TenantManager
	tm.httpClient.RetryConfig = nil
	tenant, err := tm.Tenant(context.Background(), "my-tenant")
	if tenant != nil || err == nil {
		t.Errorf("Tenant() = (%v, %v); want = (nil, error)", tenant, err)
	}
}

func TestTenantManagerJsonParseError(t *testing.T) {
	s := echoServer([]byte(`not json`), t)
	defer s.Close()

	tm := s.Client.TenantManager
	tm.httpClient.RetryConfig = nil
	tenant, err := tm.Tenant(context.Background(), "my-tenant")
	if tenant != nil || err == nil {
		t.Errorf("Tenant() = (%v, %v); want = (nil, error)", tenant, err)
	}
}
