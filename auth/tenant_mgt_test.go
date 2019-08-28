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
	"reflect"
	"testing"
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

func TestTenantManagerEmptyProjectID(t *testing.T) {
	tm := &TenantManager{}
	tc, err := tm.Tenant(context.Background(), "my-tenant")
	if tc != nil || err == nil {
		t.Errorf("Tenant() = (%v, %v); want = (nil, error)", tc, err)
	}
}

func TestTenantEmptyTenantID(t *testing.T) {
	tm := &TenantManager{}
	tc, err := tm.Tenant(context.Background(), "")
	if tc != nil || err == nil {
		t.Errorf("Tenant() = (%v, %v); want = (nil, error)", tc, err)
	}
}

func TestGetTenant(t *testing.T) {
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
		EmailSignInConfig: &EmailSignInConfig{
			PasswordRequired: true,
		},
	}
	if !reflect.DeepEqual(tenant, want) {
		t.Errorf("Tenant() = %#v; want = %#v", tenant, want)
	}

	wantURL := "/projects/mock-project-id/tenants/my-tenant"
	if s.Req[0].URL.Path != wantURL {
		t.Errorf("Tenant() URL = %q; want = %q", s.Req[0].URL.Path, wantURL)
	}
}
