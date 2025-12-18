// Package main provides tests for the RubyGems plugin.
package main

import (
	"context"
	"os"
	"testing"

	"github.com/relicta-tech/relicta-plugin-sdk/helpers"
	"github.com/relicta-tech/relicta-plugin-sdk/plugin"
)

func TestGetInfo(t *testing.T) {
	p := &RubyGemsPlugin{}
	info := p.GetInfo()

	tests := []struct {
		name     string
		check    func() bool
		errorMsg string
	}{
		{
			name:     "name is rubygems",
			check:    func() bool { return info.Name == "rubygems" },
			errorMsg: "expected name 'rubygems', got '" + info.Name + "'",
		},
		{
			name:     "version is set",
			check:    func() bool { return info.Version != "" },
			errorMsg: "expected non-empty version",
		},
		{
			name:     "version is 2.0.0",
			check:    func() bool { return info.Version == "2.0.0" },
			errorMsg: "expected version '2.0.0', got '" + info.Version + "'",
		},
		{
			name:     "description is set",
			check:    func() bool { return info.Description != "" },
			errorMsg: "expected non-empty description",
		},
		{
			name:     "description matches",
			check:    func() bool { return info.Description == "Publish gems to RubyGems.org (Ruby)" },
			errorMsg: "expected description 'Publish gems to RubyGems.org (Ruby)', got '" + info.Description + "'",
		},
		{
			name:     "author is set",
			check:    func() bool { return info.Author != "" },
			errorMsg: "expected non-empty author",
		},
		{
			name:     "author is Relicta Team",
			check:    func() bool { return info.Author == "Relicta Team" },
			errorMsg: "expected author 'Relicta Team', got '" + info.Author + "'",
		},
		{
			name:     "has at least one hook",
			check:    func() bool { return len(info.Hooks) > 0 },
			errorMsg: "expected at least one hook",
		},
		{
			name:     "config schema is set",
			check:    func() bool { return info.ConfigSchema != "" },
			errorMsg: "expected non-empty config schema",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !tt.check() {
				t.Error(tt.errorMsg)
			}
		})
	}

	// Check for PostPublish hook specifically
	t.Run("has PostPublish hook", func(t *testing.T) {
		hasPostPublish := false
		for _, hook := range info.Hooks {
			if hook == plugin.HookPostPublish {
				hasPostPublish = true
				break
			}
		}
		if !hasPostPublish {
			t.Error("expected PostPublish hook")
		}
	})
}

func TestValidate(t *testing.T) {
	p := &RubyGemsPlugin{}
	ctx := context.Background()

	tests := []struct {
		name        string
		config      map[string]any
		envVars     map[string]string
		wantValid   bool
		wantErrors  int
		errorFields []string
	}{
		{
			name:       "empty config is valid",
			config:     map[string]any{},
			wantValid:  true,
			wantErrors: 0,
		},
		{
			name:       "nil config is valid",
			config:     nil,
			wantValid:  true,
			wantErrors: 0,
		},
		{
			name: "config with gem_name is valid",
			config: map[string]any{
				"gem_name": "my-awesome-gem",
			},
			wantValid:  true,
			wantErrors: 0,
		},
		{
			name: "config with host is valid",
			config: map[string]any{
				"host": "https://rubygems.org",
			},
			wantValid:  true,
			wantErrors: 0,
		},
		{
			name: "config with all options",
			config: map[string]any{
				"gem_name": "my-awesome-gem",
				"host":     "https://rubygems.org",
				"api_key":  "test-api-key",
			},
			wantValid:  true,
			wantErrors: 0,
		},
		{
			name:    "env var fallback for api key",
			config:  map[string]any{},
			envVars: map[string]string{"GEM_HOST_API_KEY": "env-api-key"},
			wantValid:  true,
			wantErrors: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set env vars
			for k, v := range tt.envVars {
				_ = os.Setenv(k, v)
				defer func(key string) { _ = os.Unsetenv(key) }(k)
			}

			resp, err := p.Validate(ctx, tt.config)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if resp.Valid != tt.wantValid {
				t.Errorf("expected valid=%v, got valid=%v, errors=%v", tt.wantValid, resp.Valid, resp.Errors)
			}

			if len(resp.Errors) != tt.wantErrors {
				t.Errorf("expected %d errors, got %d: %v", tt.wantErrors, len(resp.Errors), resp.Errors)
			}

			// Check specific error fields if provided
			if len(tt.errorFields) > 0 {
				for _, field := range tt.errorFields {
					found := false
					for _, e := range resp.Errors {
						if e.Field == field {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("expected error for field '%s', but not found in %v", field, resp.Errors)
					}
				}
			}
		})
	}
}

func TestParseConfig(t *testing.T) {
	tests := []struct {
		name           string
		config         map[string]any
		envVars        map[string]string
		expectedHost   string
		expectedAPIKey string
	}{
		{
			name:           "defaults",
			config:         map[string]any{},
			expectedHost:   "https://rubygems.org",
			expectedAPIKey: "",
		},
		{
			name: "custom host",
			config: map[string]any{
				"host": "https://custom-gem-server.example.com",
			},
			expectedHost:   "https://custom-gem-server.example.com",
			expectedAPIKey: "",
		},
		{
			name: "custom api key",
			config: map[string]any{
				"api_key": "config-api-key",
			},
			expectedHost:   "https://rubygems.org",
			expectedAPIKey: "config-api-key",
		},
		{
			name:   "env var fallback for api key",
			config: map[string]any{},
			envVars: map[string]string{
				"GEM_HOST_API_KEY": "env-api-key",
			},
			expectedHost:   "https://rubygems.org",
			expectedAPIKey: "env-api-key",
		},
		{
			name: "config takes precedence over env var",
			config: map[string]any{
				"api_key": "config-api-key",
			},
			envVars: map[string]string{
				"GEM_HOST_API_KEY": "env-api-key",
			},
			expectedHost:   "https://rubygems.org",
			expectedAPIKey: "config-api-key",
		},
		{
			name: "all custom values",
			config: map[string]any{
				"host":    "https://private.gemserver.io",
				"api_key": "my-secret-key",
			},
			expectedHost:   "https://private.gemserver.io",
			expectedAPIKey: "my-secret-key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear and set env vars
			_ = os.Unsetenv("GEM_HOST_API_KEY")
			for k, v := range tt.envVars {
				_ = os.Setenv(k, v)
				defer func(key string) { _ = os.Unsetenv(key) }(k)
			}

			parser := helpers.NewConfigParser(tt.config)

			host := parser.GetString("host", "", "https://rubygems.org")
			apiKey := parser.GetString("api_key", "GEM_HOST_API_KEY", "")

			if host != tt.expectedHost {
				t.Errorf("host: expected '%s', got '%s'", tt.expectedHost, host)
			}
			if apiKey != tt.expectedAPIKey {
				t.Errorf("api_key: expected '%s', got '%s'", tt.expectedAPIKey, apiKey)
			}
		})
	}
}

func TestExecuteDryRun(t *testing.T) {
	p := &RubyGemsPlugin{}
	ctx := context.Background()

	tests := []struct {
		name           string
		config         map[string]any
		releaseCtx     plugin.ReleaseContext
		expectedMsg    string
		expectSuccess  bool
	}{
		{
			name:   "basic dry run",
			config: map[string]any{},
			releaseCtx: plugin.ReleaseContext{
				Version: "1.0.0",
				TagName: "v1.0.0",
			},
			expectedMsg:   "Would execute rubygems plugin",
			expectSuccess: true,
		},
		{
			name: "dry run with config",
			config: map[string]any{
				"gem_name": "my-gem",
				"host":     "https://rubygems.org",
			},
			releaseCtx: plugin.ReleaseContext{
				Version:        "2.5.1",
				TagName:        "v2.5.1",
				ReleaseType:    "minor",
				RepositoryName: "my-gem",
			},
			expectedMsg:   "Would execute rubygems plugin",
			expectSuccess: true,
		},
		{
			name: "dry run with private gem server",
			config: map[string]any{
				"host":    "https://gems.example.com",
				"api_key": "test-key",
			},
			releaseCtx: plugin.ReleaseContext{
				Version: "0.1.0",
				TagName: "v0.1.0",
			},
			expectedMsg:   "Would execute rubygems plugin",
			expectSuccess: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := plugin.ExecuteRequest{
				Hook:    plugin.HookPostPublish,
				Config:  tt.config,
				Context: tt.releaseCtx,
				DryRun:  true,
			}

			resp, err := p.Execute(ctx, req)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if resp.Success != tt.expectSuccess {
				t.Errorf("expected success=%v, got success=%v, error=%s", tt.expectSuccess, resp.Success, resp.Error)
			}

			if resp.Message != tt.expectedMsg {
				t.Errorf("expected message '%s', got '%s'", tt.expectedMsg, resp.Message)
			}
		})
	}
}

func TestExecuteRealRun(t *testing.T) {
	p := &RubyGemsPlugin{}
	ctx := context.Background()

	tests := []struct {
		name          string
		config        map[string]any
		releaseCtx    plugin.ReleaseContext
		expectedMsg   string
		expectSuccess bool
	}{
		{
			name:   "real execution",
			config: map[string]any{},
			releaseCtx: plugin.ReleaseContext{
				Version: "1.0.0",
			},
			expectedMsg:   "RubyGems plugin executed successfully",
			expectSuccess: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := plugin.ExecuteRequest{
				Hook:    plugin.HookPostPublish,
				Config:  tt.config,
				Context: tt.releaseCtx,
				DryRun:  false,
			}

			resp, err := p.Execute(ctx, req)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if resp.Success != tt.expectSuccess {
				t.Errorf("expected success=%v, got success=%v", tt.expectSuccess, resp.Success)
			}

			if resp.Message != tt.expectedMsg {
				t.Errorf("expected message '%s', got '%s'", tt.expectedMsg, resp.Message)
			}
		})
	}
}

func TestExecuteUnhandledHook(t *testing.T) {
	p := &RubyGemsPlugin{}
	ctx := context.Background()

	unhandledHooks := []plugin.Hook{
		plugin.HookPreInit,
		plugin.HookPostInit,
		plugin.HookPrePlan,
		plugin.HookPostPlan,
		plugin.HookPreVersion,
		plugin.HookPostVersion,
		plugin.HookPreNotes,
		plugin.HookPostNotes,
		plugin.HookPreApprove,
		plugin.HookPostApprove,
		plugin.HookPrePublish,
		plugin.HookOnSuccess,
		plugin.HookOnError,
	}

	for _, hook := range unhandledHooks {
		t.Run(string(hook), func(t *testing.T) {
			req := plugin.ExecuteRequest{
				Hook:   hook,
				Config: map[string]any{},
				DryRun: true,
			}

			resp, err := p.Execute(ctx, req)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if !resp.Success {
				t.Error("expected success for unhandled hook")
			}

			expectedMsg := "Hook " + string(hook) + " not handled"
			if resp.Message != expectedMsg {
				t.Errorf("expected message '%s', got '%s'", expectedMsg, resp.Message)
			}
		})
	}
}

func TestValidationBuilderIntegration(t *testing.T) {
	// Test that the validation builder works correctly with RubyGems plugin
	tests := []struct {
		name       string
		buildFunc  func() *plugin.ValidateResponse
		wantValid  bool
		wantErrors int
	}{
		{
			name: "no errors",
			buildFunc: func() *plugin.ValidateResponse {
				vb := helpers.NewValidationBuilder()
				return vb.Build()
			},
			wantValid:  true,
			wantErrors: 0,
		},
		{
			name: "with error",
			buildFunc: func() *plugin.ValidateResponse {
				vb := helpers.NewValidationBuilder()
				vb.AddError("test_field", "test error message")
				return vb.Build()
			},
			wantValid:  false,
			wantErrors: 1,
		},
		{
			name: "multiple errors",
			buildFunc: func() *plugin.ValidateResponse {
				vb := helpers.NewValidationBuilder()
				vb.AddError("field1", "error 1")
				vb.AddError("field2", "error 2")
				vb.AddErrorWithCode("field3", "error 3", "ERR_CODE")
				return vb.Build()
			},
			wantValid:  false,
			wantErrors: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := tt.buildFunc()

			if resp.Valid != tt.wantValid {
				t.Errorf("expected valid=%v, got valid=%v", tt.wantValid, resp.Valid)
			}

			if len(resp.Errors) != tt.wantErrors {
				t.Errorf("expected %d errors, got %d", tt.wantErrors, len(resp.Errors))
			}
		})
	}
}
