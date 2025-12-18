// Package main provides tests for the RubyGems plugin.
package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/relicta-tech/relicta-plugin-sdk/helpers"
	"github.com/relicta-tech/relicta-plugin-sdk/plugin"
)

// MockCommandExecutor is a mock implementation of CommandExecutor for testing.
type MockCommandExecutor struct {
	RunFunc func(ctx context.Context, name string, args []string, env []string) ([]byte, error)
	Calls   []MockCall
}

// MockCall records a call to the executor.
type MockCall struct {
	Name string
	Args []string
	Env  []string
}

// Run implements CommandExecutor.
func (m *MockCommandExecutor) Run(ctx context.Context, name string, args []string, env []string) ([]byte, error) {
	m.Calls = append(m.Calls, MockCall{Name: name, Args: args, Env: env})
	if m.RunFunc != nil {
		return m.RunFunc(ctx, name, args, env)
	}
	return []byte("mock output"), nil
}

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
			name: "config with valid host is valid",
			config: map[string]any{
				"host": "https://rubygems.org",
			},
			wantValid:  true,
			wantErrors: 0,
		},
		{
			name: "config with custom https host is valid",
			config: map[string]any{
				"host": "https://gems.example.com",
			},
			wantValid:  true,
			wantErrors: 0,
		},
		{
			name: "config with localhost http is valid",
			config: map[string]any{
				"host": "http://localhost:9292",
			},
			wantValid:  true,
			wantErrors: 0,
		},
		{
			name: "config with 127.0.0.1 http is valid",
			config: map[string]any{
				"host": "http://127.0.0.1:9292",
			},
			wantValid:  true,
			wantErrors: 0,
		},
		{
			name: "config with http non-localhost is invalid",
			config: map[string]any{
				"host": "http://example.com",
			},
			wantValid:   false,
			wantErrors:  1,
			errorFields: []string{"host"},
		},
		{
			name: "config with valid gem_path",
			config: map[string]any{
				"gem_path": "pkg/my-gem-1.0.0.gem",
			},
			wantValid:  true,
			wantErrors: 0,
		},
		{
			name: "config with glob gem_path",
			config: map[string]any{
				"gem_path": "pkg/*.gem",
			},
			wantValid:  true,
			wantErrors: 0,
		},
		{
			name: "config with absolute gem_path",
			config: map[string]any{
				"gem_path": "/var/tmp/my-gem-1.0.0.gem",
			},
			wantValid:  true,
			wantErrors: 0,
		},
		{
			name: "config with path traversal in gem_path",
			config: map[string]any{
				"gem_path": "../../../etc/passwd.gem",
			},
			wantValid:   false,
			wantErrors:  1,
			errorFields: []string{"gem_path"},
		},
		{
			name: "config with path traversal in glob pattern",
			config: map[string]any{
				"gem_path": "../../*.gem",
			},
			wantValid:   false,
			wantErrors:  1,
			errorFields: []string{"gem_path"},
		},
		{
			name: "config with valid OTP",
			config: map[string]any{
				"otp": "123456",
			},
			wantValid:  true,
			wantErrors: 0,
		},
		{
			name: "config with invalid OTP (too short)",
			config: map[string]any{
				"otp": "12345",
			},
			wantValid:   false,
			wantErrors:  1,
			errorFields: []string{"otp"},
		},
		{
			name: "config with invalid OTP (non-numeric)",
			config: map[string]any{
				"otp": "abcdef",
			},
			wantValid:   false,
			wantErrors:  1,
			errorFields: []string{"otp"},
		},
		{
			name: "config with all options",
			config: map[string]any{
				"api_key":  "test-api-key",
				"host":     "https://rubygems.org",
				"gem_path": "pkg/*.gem",
				"otp":      "123456",
			},
			wantValid:  true,
			wantErrors: 0,
		},
		{
			name:       "env var fallback for api key",
			config:     map[string]any{},
			envVars:    map[string]string{"GEM_HOST_API_KEY": "env-api-key"},
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
		name            string
		config          map[string]any
		envVars         map[string]string
		expectedHost    string
		expectedAPIKey  string
		expectedGemPath string
		expectedOTP     string
	}{
		{
			name:            "defaults",
			config:          map[string]any{},
			expectedHost:    "https://rubygems.org",
			expectedAPIKey:  "",
			expectedGemPath: "pkg/*.gem",
			expectedOTP:     "",
		},
		{
			name: "custom host",
			config: map[string]any{
				"host": "https://custom-gem-server.example.com",
			},
			expectedHost:    "https://custom-gem-server.example.com",
			expectedAPIKey:  "",
			expectedGemPath: "pkg/*.gem",
			expectedOTP:     "",
		},
		{
			name: "custom api key",
			config: map[string]any{
				"api_key": "config-api-key",
			},
			expectedHost:    "https://rubygems.org",
			expectedAPIKey:  "config-api-key",
			expectedGemPath: "pkg/*.gem",
			expectedOTP:     "",
		},
		{
			name:   "env var fallback for api key",
			config: map[string]any{},
			envVars: map[string]string{
				"GEM_HOST_API_KEY": "env-api-key",
			},
			expectedHost:    "https://rubygems.org",
			expectedAPIKey:  "env-api-key",
			expectedGemPath: "pkg/*.gem",
			expectedOTP:     "",
		},
		{
			name: "config takes precedence over env var",
			config: map[string]any{
				"api_key": "config-api-key",
			},
			envVars: map[string]string{
				"GEM_HOST_API_KEY": "env-api-key",
			},
			expectedHost:    "https://rubygems.org",
			expectedAPIKey:  "config-api-key",
			expectedGemPath: "pkg/*.gem",
			expectedOTP:     "",
		},
		{
			name: "custom gem_path",
			config: map[string]any{
				"gem_path": "dist/my-gem-{{version}}.gem",
			},
			expectedHost:    "https://rubygems.org",
			expectedAPIKey:  "",
			expectedGemPath: "dist/my-gem-{{version}}.gem",
			expectedOTP:     "",
		},
		{
			name: "with OTP",
			config: map[string]any{
				"otp": "123456",
			},
			expectedHost:    "https://rubygems.org",
			expectedAPIKey:  "",
			expectedGemPath: "pkg/*.gem",
			expectedOTP:     "123456",
		},
		{
			name: "all custom values",
			config: map[string]any{
				"host":     "https://private.gemserver.io",
				"api_key":  "my-secret-key",
				"gem_path": "build/*.gem",
				"otp":      "654321",
			},
			expectedHost:    "https://private.gemserver.io",
			expectedAPIKey:  "my-secret-key",
			expectedGemPath: "build/*.gem",
			expectedOTP:     "654321",
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

			p := &RubyGemsPlugin{}
			cfg := p.parseConfig(tt.config)

			if cfg.Host != tt.expectedHost {
				t.Errorf("host: expected '%s', got '%s'", tt.expectedHost, cfg.Host)
			}
			if cfg.APIKey != tt.expectedAPIKey {
				t.Errorf("api_key: expected '%s', got '%s'", tt.expectedAPIKey, cfg.APIKey)
			}
			if cfg.GemPath != tt.expectedGemPath {
				t.Errorf("gem_path: expected '%s', got '%s'", tt.expectedGemPath, cfg.GemPath)
			}
			if cfg.OTP != tt.expectedOTP {
				t.Errorf("otp: expected '%s', got '%s'", tt.expectedOTP, cfg.OTP)
			}
		})
	}
}

func TestExecuteDryRun(t *testing.T) {
	// Create a temporary directory with test gem files
	tmpDir, err := os.MkdirTemp("", "rubygems-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Create test gem files
	gemFile := filepath.Join(tmpDir, "test-gem-1.0.0.gem")
	if err := os.WriteFile(gemFile, []byte("fake gem content"), 0644); err != nil {
		t.Fatalf("failed to create test gem file: %v", err)
	}

	ctx := context.Background()

	tests := []struct {
		name          string
		config        map[string]any
		releaseCtx    plugin.ReleaseContext
		expectedMsg   string
		expectSuccess bool
	}{
		{
			name: "basic dry run with explicit gem path",
			config: map[string]any{
				"gem_path": gemFile,
			},
			releaseCtx: plugin.ReleaseContext{
				Version: "1.0.0",
				TagName: "v1.0.0",
			},
			expectedMsg:   "Would push 1 gem(s) to https://rubygems.org",
			expectSuccess: true,
		},
		{
			name: "dry run with custom host",
			config: map[string]any{
				"gem_path": gemFile,
				"host":     "https://gems.example.com",
			},
			releaseCtx: plugin.ReleaseContext{
				Version: "2.5.1",
				TagName: "v2.5.1",
			},
			expectedMsg:   "Would push 1 gem(s) to https://gems.example.com",
			expectSuccess: true,
		},
		{
			name: "dry run with OTP",
			config: map[string]any{
				"gem_path": gemFile,
				"otp":      "123456",
			},
			releaseCtx: plugin.ReleaseContext{
				Version: "0.1.0",
				TagName: "v0.1.0",
			},
			expectedMsg:   "Would push 1 gem(s) to https://rubygems.org",
			expectSuccess: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &RubyGemsPlugin{}
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
	// Create a temporary directory with test gem files
	tmpDir, err := os.MkdirTemp("", "rubygems-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Create test gem files
	gemFile := filepath.Join(tmpDir, "test-gem-1.0.0.gem")
	if err := os.WriteFile(gemFile, []byte("fake gem content"), 0644); err != nil {
		t.Fatalf("failed to create test gem file: %v", err)
	}

	ctx := context.Background()

	tests := []struct {
		name          string
		config        map[string]any
		releaseCtx    plugin.ReleaseContext
		mockFunc      func(ctx context.Context, name string, args []string, env []string) ([]byte, error)
		expectedMsg   string
		expectSuccess bool
		expectError   string
		verifyCall    func(t *testing.T, calls []MockCall)
	}{
		{
			name: "successful push to default host",
			config: map[string]any{
				"gem_path": gemFile,
				"api_key":  "test-api-key",
			},
			releaseCtx: plugin.ReleaseContext{
				Version: "1.0.0",
			},
			mockFunc: func(ctx context.Context, name string, args []string, env []string) ([]byte, error) {
				return []byte("Successfully registered gem: test-gem (1.0.0)"), nil
			},
			expectedMsg:   "Successfully pushed 1 gem(s) to https://rubygems.org",
			expectSuccess: true,
			verifyCall: func(t *testing.T, calls []MockCall) {
				if len(calls) != 1 {
					t.Errorf("expected 1 call, got %d", len(calls))
					return
				}
				call := calls[0]
				if call.Name != "gem" {
					t.Errorf("expected command 'gem', got '%s'", call.Name)
				}
				if call.Args[0] != "push" {
					t.Errorf("expected first arg 'push', got '%s'", call.Args[0])
				}
				// Check API key is in environment
				found := false
				for _, env := range call.Env {
					if env == "GEM_HOST_API_KEY=test-api-key" {
						found = true
						break
					}
				}
				if !found {
					t.Error("expected GEM_HOST_API_KEY in environment")
				}
			},
		},
		{
			name: "successful push to custom host",
			config: map[string]any{
				"gem_path": gemFile,
				"api_key":  "test-api-key",
				"host":     "https://gems.example.com",
			},
			releaseCtx: plugin.ReleaseContext{
				Version: "1.0.0",
			},
			mockFunc: func(ctx context.Context, name string, args []string, env []string) ([]byte, error) {
				return []byte("Successfully registered gem"), nil
			},
			expectedMsg:   "Successfully pushed 1 gem(s) to https://gems.example.com",
			expectSuccess: true,
			verifyCall: func(t *testing.T, calls []MockCall) {
				if len(calls) != 1 {
					t.Errorf("expected 1 call, got %d", len(calls))
					return
				}
				call := calls[0]
				// Check --host flag is present
				hostFlagFound := false
				for i, arg := range call.Args {
					if arg == "--host" && i+1 < len(call.Args) && call.Args[i+1] == "https://gems.example.com" {
						hostFlagFound = true
						break
					}
				}
				if !hostFlagFound {
					t.Errorf("expected --host flag with value, got args: %v", call.Args)
				}
			},
		},
		{
			name: "successful push with OTP",
			config: map[string]any{
				"gem_path": gemFile,
				"api_key":  "test-api-key",
				"otp":      "123456",
			},
			releaseCtx: plugin.ReleaseContext{
				Version: "1.0.0",
			},
			mockFunc: func(ctx context.Context, name string, args []string, env []string) ([]byte, error) {
				return []byte("Successfully registered gem"), nil
			},
			expectedMsg:   "Successfully pushed 1 gem(s) to https://rubygems.org",
			expectSuccess: true,
			verifyCall: func(t *testing.T, calls []MockCall) {
				if len(calls) != 1 {
					t.Errorf("expected 1 call, got %d", len(calls))
					return
				}
				call := calls[0]
				// Check --otp flag is present
				otpFlagFound := false
				for i, arg := range call.Args {
					if arg == "--otp" && i+1 < len(call.Args) && call.Args[i+1] == "123456" {
						otpFlagFound = true
						break
					}
				}
				if !otpFlagFound {
					t.Errorf("expected --otp flag with value, got args: %v", call.Args)
				}
			},
		},
		{
			name: "missing api key",
			config: map[string]any{
				"gem_path": gemFile,
			},
			releaseCtx: plugin.ReleaseContext{
				Version: "1.0.0",
			},
			expectSuccess: false,
			expectError:   "API key is required",
		},
		{
			name: "push failure",
			config: map[string]any{
				"gem_path": gemFile,
				"api_key":  "invalid-key",
			},
			releaseCtx: plugin.ReleaseContext{
				Version: "1.0.0",
			},
			mockFunc: func(ctx context.Context, name string, args []string, env []string) ([]byte, error) {
				return []byte("ERROR:  You do not have permission to push to this gem"), errors.New("exit status 1")
			},
			expectSuccess: false,
			expectError:   "failed to push gem",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear API key env var
			_ = os.Unsetenv("GEM_HOST_API_KEY")

			mockExec := &MockCommandExecutor{
				RunFunc: tt.mockFunc,
			}
			p := &RubyGemsPlugin{
				executor: mockExec,
			}

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
				t.Errorf("expected success=%v, got success=%v, error=%s", tt.expectSuccess, resp.Success, resp.Error)
			}

			if tt.expectedMsg != "" && resp.Message != tt.expectedMsg {
				t.Errorf("expected message '%s', got '%s'", tt.expectedMsg, resp.Message)
			}

			if tt.expectError != "" && (resp.Error == "" || !contains(resp.Error, tt.expectError)) {
				t.Errorf("expected error containing '%s', got '%s'", tt.expectError, resp.Error)
			}

			if tt.verifyCall != nil {
				tt.verifyCall(t, mockExec.Calls)
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

func TestValidateHost(t *testing.T) {
	tests := []struct {
		name      string
		host      string
		wantError bool
		errorMsg  string
	}{
		{
			name:      "empty host is valid",
			host:      "",
			wantError: false,
		},
		{
			name:      "rubygems.org is valid",
			host:      "https://rubygems.org",
			wantError: false,
		},
		{
			name:      "custom https host is valid",
			host:      "https://gems.example.com",
			wantError: false,
		},
		{
			name:      "localhost http is valid",
			host:      "http://localhost:9292",
			wantError: false,
		},
		{
			name:      "127.0.0.1 http is valid",
			host:      "http://127.0.0.1:9292",
			wantError: false,
		},
		{
			name:      "::1 http is valid",
			host:      "http://[::1]:9292",
			wantError: false,
		},
		{
			name:      "non-localhost http is invalid",
			host:      "http://example.com",
			wantError: true,
			errorMsg:  "only HTTPS URLs are allowed",
		},
		{
			name:      "invalid URL is invalid",
			host:      "not-a-url",
			wantError: true,
			errorMsg:  "only HTTPS URLs are allowed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateHost(tt.host)
			if tt.wantError {
				if err == nil {
					t.Error("expected error, got nil")
				} else if tt.errorMsg != "" && !contains(err.Error(), tt.errorMsg) {
					t.Errorf("expected error containing '%s', got '%s'", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestValidateGemPathPattern(t *testing.T) {
	tests := []struct {
		name      string
		pattern   string
		wantError bool
		errorMsg  string
	}{
		{
			name:      "valid simple gem path",
			pattern:   "my-gem-1.0.0.gem",
			wantError: false,
		},
		{
			name:      "valid gem path in subdirectory",
			pattern:   "pkg/my-gem-1.0.0.gem",
			wantError: false,
		},
		{
			name:      "valid glob pattern",
			pattern:   "pkg/*.gem",
			wantError: false,
		},
		{
			name:      "valid absolute path",
			pattern:   "/var/tmp/my-gem.gem",
			wantError: false,
		},
		{
			name:      "empty pattern is invalid",
			pattern:   "",
			wantError: true,
			errorMsg:  "gem path pattern cannot be empty",
		},
		{
			name:      "path traversal is invalid",
			pattern:   "../parent/gem.gem",
			wantError: true,
			errorMsg:  "path traversal detected",
		},
		{
			name:      "path traversal in middle is invalid",
			pattern:   "pkg/../../../etc/passwd.gem",
			wantError: true,
			errorMsg:  "path traversal detected",
		},
		{
			name:      "path traversal with glob is invalid",
			pattern:   "../../*.gem",
			wantError: true,
			errorMsg:  "path traversal detected",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateGemPathPattern(tt.pattern)
			if tt.wantError {
				if err == nil {
					t.Error("expected error, got nil")
				} else if tt.errorMsg != "" && !contains(err.Error(), tt.errorMsg) {
					t.Errorf("expected error containing '%s', got '%s'", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestValidateGemPath(t *testing.T) {
	tests := []struct {
		name      string
		path      string
		wantError bool
		errorMsg  string
	}{
		{
			name:      "valid simple gem path",
			path:      "my-gem-1.0.0.gem",
			wantError: false,
		},
		{
			name:      "valid gem path in subdirectory",
			path:      "pkg/my-gem-1.0.0.gem",
			wantError: false,
		},
		{
			name:      "empty path is invalid",
			path:      "",
			wantError: true,
			errorMsg:  "gem path cannot be empty",
		},
		{
			name:      "absolute path is invalid",
			path:      "/absolute/path/gem.gem",
			wantError: true,
			errorMsg:  "absolute paths are not allowed",
		},
		{
			name:      "path traversal is invalid",
			path:      "../parent/gem.gem",
			wantError: true,
			errorMsg:  "path traversal detected",
		},
		{
			name:      "path traversal in middle is invalid",
			path:      "pkg/../../../etc/passwd.gem",
			wantError: true,
			errorMsg:  "path traversal detected",
		},
		{
			name:      "missing gem extension is invalid",
			path:      "pkg/my-gem-1.0.0",
			wantError: true,
			errorMsg:  "gem path must end with .gem extension",
		},
		{
			name:      "wrong extension is invalid",
			path:      "pkg/my-gem-1.0.0.tar.gz",
			wantError: true,
			errorMsg:  "gem path must end with .gem extension",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateGemPath(tt.path)
			if tt.wantError {
				if err == nil {
					t.Error("expected error, got nil")
				} else if tt.errorMsg != "" && !contains(err.Error(), tt.errorMsg) {
					t.Errorf("expected error containing '%s', got '%s'", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestValidateOTP(t *testing.T) {
	tests := []struct {
		name      string
		otp       string
		wantError bool
		errorMsg  string
	}{
		{
			name:      "empty OTP is valid (optional)",
			otp:       "",
			wantError: false,
		},
		{
			name:      "valid 6-digit OTP",
			otp:       "123456",
			wantError: false,
		},
		{
			name:      "valid OTP with zeros",
			otp:       "000000",
			wantError: false,
		},
		{
			name:      "too short OTP",
			otp:       "12345",
			wantError: true,
			errorMsg:  "OTP must be a 6-digit code",
		},
		{
			name:      "too long OTP",
			otp:       "1234567",
			wantError: true,
			errorMsg:  "OTP must be a 6-digit code",
		},
		{
			name:      "non-numeric OTP",
			otp:       "abcdef",
			wantError: true,
			errorMsg:  "OTP must be a 6-digit code",
		},
		{
			name:      "mixed alphanumeric OTP",
			otp:       "12ab34",
			wantError: true,
			errorMsg:  "OTP must be a 6-digit code",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateOTP(tt.otp)
			if tt.wantError {
				if err == nil {
					t.Error("expected error, got nil")
				} else if tt.errorMsg != "" && !contains(err.Error(), tt.errorMsg) {
					t.Errorf("expected error containing '%s', got '%s'", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestResolveGemPath(t *testing.T) {
	// Create a temporary directory with test gem files
	tmpDir, err := os.MkdirTemp("", "rubygems-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Create test gem files
	gemFile1 := filepath.Join(tmpDir, "gem-1.0.0.gem")
	gemFile2 := filepath.Join(tmpDir, "gem-1.0.1.gem")
	if err := os.WriteFile(gemFile1, []byte("gem1"), 0644); err != nil {
		t.Fatalf("failed to create test gem file: %v", err)
	}
	if err := os.WriteFile(gemFile2, []byte("gem2"), 0644); err != nil {
		t.Fatalf("failed to create test gem file: %v", err)
	}

	p := &RubyGemsPlugin{}

	tests := []struct {
		name          string
		pattern       string
		version       string
		expectedCount int
		wantError     bool
	}{
		{
			name:          "single file path",
			pattern:       gemFile1,
			version:       "1.0.0",
			expectedCount: 1,
			wantError:     false,
		},
		{
			name:          "glob pattern",
			pattern:       filepath.Join(tmpDir, "*.gem"),
			version:       "1.0.0",
			expectedCount: 2,
			wantError:     false,
		},
		{
			name:          "version substitution",
			pattern:       filepath.Join(tmpDir, "gem-{{version}}.gem"),
			version:       "1.0.0",
			expectedCount: 1,
			wantError:     false,
		},
		{
			name:          "no matches",
			pattern:       filepath.Join(tmpDir, "nonexistent-*.gem"),
			version:       "1.0.0",
			expectedCount: 0,
			wantError:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := p.resolveGemPath(tt.pattern, tt.version)
			if tt.wantError {
				if err == nil {
					t.Error("expected error, got nil")
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if len(result) != tt.expectedCount {
					t.Errorf("expected %d results, got %d: %v", tt.expectedCount, len(result), result)
				}
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

func TestSecurityValidationInExecute(t *testing.T) {
	// Create a temporary directory with test gem files
	tmpDir, err := os.MkdirTemp("", "rubygems-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Create test gem file
	gemFile := filepath.Join(tmpDir, "test-gem-1.0.0.gem")
	if err := os.WriteFile(gemFile, []byte("fake gem content"), 0644); err != nil {
		t.Fatalf("failed to create test gem file: %v", err)
	}

	ctx := context.Background()

	tests := []struct {
		name          string
		config        map[string]any
		expectSuccess bool
		expectError   string
	}{
		{
			name: "http host rejected",
			config: map[string]any{
				"gem_path": gemFile,
				"host":     "http://malicious.example.com",
			},
			expectSuccess: false,
			expectError:   "only HTTPS URLs are allowed",
		},
		{
			name: "invalid OTP rejected",
			config: map[string]any{
				"gem_path": gemFile,
				"otp":      "invalid",
			},
			expectSuccess: false,
			expectError:   "OTP must be a 6-digit code",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &RubyGemsPlugin{}
			req := plugin.ExecuteRequest{
				Hook:    plugin.HookPostPublish,
				Config:  tt.config,
				Context: plugin.ReleaseContext{Version: "1.0.0"},
				DryRun:  false,
			}

			resp, err := p.Execute(ctx, req)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if resp.Success != tt.expectSuccess {
				t.Errorf("expected success=%v, got success=%v, error=%s", tt.expectSuccess, resp.Success, resp.Error)
			}

			if tt.expectError != "" && !contains(resp.Error, tt.expectError) {
				t.Errorf("expected error containing '%s', got '%s'", tt.expectError, resp.Error)
			}
		})
	}
}

func TestIsPrivateIP(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		expected bool
	}{
		{"private 10.x.x.x", "10.0.0.1", true},
		{"private 172.16.x.x", "172.16.0.1", true},
		{"private 192.168.x.x", "192.168.1.1", true},
		{"loopback 127.0.0.1", "127.0.0.1", true},
		{"link-local", "169.254.1.1", true},
		{"aws metadata", "169.254.169.254", true},
		{"public IP", "8.8.8.8", false},
		{"public IP 2", "1.1.1.1", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := parseIP(tt.ip)
			if ip == nil {
				t.Fatalf("failed to parse IP: %s", tt.ip)
			}
			result := isPrivateIP(ip)
			if result != tt.expected {
				t.Errorf("isPrivateIP(%s) = %v, want %v", tt.ip, result, tt.expected)
			}
		})
	}
}

func TestNoGemFilesFound(t *testing.T) {
	// Create a temporary directory without gem files
	tmpDir, err := os.MkdirTemp("", "rubygems-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	ctx := context.Background()
	p := &RubyGemsPlugin{}

	req := plugin.ExecuteRequest{
		Hook: plugin.HookPostPublish,
		Config: map[string]any{
			"gem_path": filepath.Join(tmpDir, "*.gem"),
		},
		Context: plugin.ReleaseContext{Version: "1.0.0"},
		DryRun:  true,
	}

	resp, err := p.Execute(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.Success {
		t.Error("expected failure when no gem files found")
	}

	if !contains(resp.Error, "no gem files found") {
		t.Errorf("expected error about no gem files, got: %s", resp.Error)
	}
}

// Helper functions

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstr(s, substr))
}

func containsSubstr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func parseIP(s string) []byte {
	var ip [4]byte
	parts := splitIP(s)
	if len(parts) != 4 {
		return nil
	}
	for i, p := range parts {
		n := parseOctet(p)
		if n < 0 || n > 255 {
			return nil
		}
		ip[i] = byte(n)
	}
	return ip[:]
}

func splitIP(s string) []string {
	var parts []string
	var current string
	for _, c := range s {
		if c == '.' {
			parts = append(parts, current)
			current = ""
		} else {
			current += string(c)
		}
	}
	parts = append(parts, current)
	return parts
}

func parseOctet(s string) int {
	if len(s) == 0 || len(s) > 3 {
		return -1
	}
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return -1
		}
		n = n*10 + int(c-'0')
	}
	return n
}
