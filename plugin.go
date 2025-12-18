// Package main implements the RubyGems plugin for Relicta.
package main

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/relicta-tech/relicta-plugin-sdk/helpers"
	"github.com/relicta-tech/relicta-plugin-sdk/plugin"
)

// Security validation patterns.
var (
	// otpPattern validates OTP codes (6 digits).
	otpPattern = regexp.MustCompile(`^[0-9]{6}$`)
)

// CommandExecutor executes shell commands. Used for testing.
type CommandExecutor interface {
	Run(ctx context.Context, name string, args []string, env []string) ([]byte, error)
}

// RealCommandExecutor executes real shell commands.
type RealCommandExecutor struct{}

// Run executes a command and returns combined output.
func (e *RealCommandExecutor) Run(ctx context.Context, name string, args []string, env []string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	if len(env) > 0 {
		cmd.Env = append(os.Environ(), env...)
	}
	return cmd.CombinedOutput()
}

// RubyGemsPlugin implements the Publish gems to RubyGems.org (Ruby) plugin.
type RubyGemsPlugin struct {
	// executor is used for executing shell commands. If nil, uses RealCommandExecutor.
	executor CommandExecutor
}

// getExecutor returns the command executor, defaulting to RealCommandExecutor.
func (p *RubyGemsPlugin) getExecutor() CommandExecutor {
	if p.executor != nil {
		return p.executor
	}
	return &RealCommandExecutor{}
}

// Config represents the RubyGems plugin configuration.
type Config struct {
	APIKey  string
	Host    string
	GemPath string
	OTP     string
}

// Well-known trusted hosts that skip DNS resolution.
var trustedHosts = map[string]bool{
	"rubygems.org":     true,
	"www.rubygems.org": true,
}

// validateHost validates that a host URL is safe (SSRF protection).
func validateHost(rawURL string) error {
	if rawURL == "" {
		return nil
	}

	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}

	host := parsedURL.Hostname()

	// Allow localhost for testing purposes
	isLocalhost := host == "localhost" || host == "127.0.0.1" || host == "::1"

	// Require HTTPS for non-localhost URLs
	if parsedURL.Scheme != "https" && !isLocalhost {
		return fmt.Errorf("only HTTPS URLs are allowed (got %s)", parsedURL.Scheme)
	}

	// For localhost, allow HTTP but skip the private IP check
	if isLocalhost {
		return nil
	}

	// Skip DNS resolution for trusted hosts
	if trustedHosts[host] {
		return nil
	}

	// Resolve hostname to check for private IPs (SSRF protection)
	ips, err := net.LookupIP(host)
	if err != nil {
		// If DNS resolution fails, we still allow the request but log a warning
		// This handles cases where DNS is temporarily unavailable
		// The actual gem push will fail if the host is unreachable
		return nil
	}

	for _, ip := range ips {
		if isPrivateIP(ip) {
			return fmt.Errorf("URLs pointing to private networks are not allowed")
		}
	}

	return nil
}

// isPrivateIP checks if an IP address is in a private/reserved range.
func isPrivateIP(ip net.IP) bool {
	// Private IPv4 ranges
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16", // Link-local
		"0.0.0.0/8",
	}

	// Cloud metadata endpoints
	cloudMetadata := []string{
		"169.254.169.254/32", // AWS/GCP/Azure metadata
		"fd00:ec2::254/128",  // AWS IMDSv2 IPv6
	}

	allRanges := append(privateRanges, cloudMetadata...)

	for _, cidr := range allRanges {
		_, block, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if block.Contains(ip) {
			return true
		}
	}

	// Check for IPv6 private ranges
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsPrivate() {
		return true
	}

	return false
}

// validateGemPath validates a gem file path to prevent path traversal.
func validateGemPath(path string) error {
	if path == "" {
		return fmt.Errorf("gem path cannot be empty")
	}

	// Clean the path
	cleaned := filepath.Clean(path)

	// Check for absolute paths (potential escape from working directory)
	if filepath.IsAbs(cleaned) {
		return fmt.Errorf("absolute paths are not allowed")
	}

	// Check for path traversal attempts
	if strings.HasPrefix(cleaned, "..") || strings.Contains(cleaned, string(filepath.Separator)+"..") {
		return fmt.Errorf("path traversal detected: cannot use '..' to escape working directory")
	}

	// Must end with .gem extension
	if !strings.HasSuffix(cleaned, ".gem") {
		return fmt.Errorf("gem path must end with .gem extension")
	}

	return nil
}

// validateGemPathPattern validates a gem path pattern to prevent path traversal.
// This is used to validate the original pattern before glob resolution.
func validateGemPathPattern(pattern string) error {
	if pattern == "" {
		return fmt.Errorf("gem path pattern cannot be empty")
	}

	// Check for path traversal attempts
	if strings.Contains(pattern, "..") {
		return fmt.Errorf("path traversal detected: cannot use '..' in gem path")
	}

	return nil
}

// validateOTP validates an OTP code format.
func validateOTP(otp string) error {
	if otp == "" {
		return nil // OTP is optional
	}
	if !otpPattern.MatchString(otp) {
		return fmt.Errorf("OTP must be a 6-digit code")
	}
	return nil
}

// GetInfo returns plugin metadata.
func (p *RubyGemsPlugin) GetInfo() plugin.Info {
	return plugin.Info{
		Name:        "rubygems",
		Version:     "2.0.0",
		Description: "Publish gems to RubyGems.org (Ruby)",
		Author:      "Relicta Team",
		Hooks: []plugin.Hook{
			plugin.HookPostPublish,
		},
		ConfigSchema: `{
			"type": "object",
			"properties": {
				"api_key": {"type": "string", "description": "RubyGems API key (or use GEM_HOST_API_KEY env)"},
				"host": {"type": "string", "description": "RubyGems host URL", "default": "https://rubygems.org"},
				"gem_path": {"type": "string", "description": "Path to gem file or glob pattern", "default": "pkg/*.gem"},
				"otp": {"type": "string", "description": "One-time password for 2FA (optional)"}
			}
		}`,
	}
}

// Execute runs the plugin for a given hook.
func (p *RubyGemsPlugin) Execute(ctx context.Context, req plugin.ExecuteRequest) (*plugin.ExecuteResponse, error) {
	cfg := p.parseConfig(req.Config)

	switch req.Hook {
	case plugin.HookPostPublish:
		return p.pushGem(ctx, cfg, req.Context, req.DryRun)
	default:
		return &plugin.ExecuteResponse{
			Success: true,
			Message: fmt.Sprintf("Hook %s not handled", req.Hook),
		}, nil
	}
}

// pushGem executes the gem push command.
func (p *RubyGemsPlugin) pushGem(ctx context.Context, cfg *Config, releaseCtx plugin.ReleaseContext, dryRun bool) (*plugin.ExecuteResponse, error) {
	// Security validation
	if err := validateHost(cfg.Host); err != nil {
		return &plugin.ExecuteResponse{
			Success: false,
			Error:   fmt.Sprintf("invalid host configuration: %v", err),
		}, nil
	}

	if err := validateOTP(cfg.OTP); err != nil {
		return &plugin.ExecuteResponse{
			Success: false,
			Error:   fmt.Sprintf("invalid OTP configuration: %v", err),
		}, nil
	}

	// Validate the gem path pattern for path traversal before resolution
	// This prevents "../" attacks while still allowing absolute paths from globs
	if err := validateGemPathPattern(cfg.GemPath); err != nil {
		return &plugin.ExecuteResponse{
			Success: false,
			Error:   fmt.Sprintf("invalid gem path pattern: %v", err),
		}, nil
	}

	// Resolve gem path (handle glob patterns)
	gemFiles, err := p.resolveGemPath(cfg.GemPath, releaseCtx.Version)
	if err != nil {
		return &plugin.ExecuteResponse{
			Success: false,
			Error:   fmt.Sprintf("failed to resolve gem path: %v", err),
		}, nil
	}

	if len(gemFiles) == 0 {
		return &plugin.ExecuteResponse{
			Success: false,
			Error:   fmt.Sprintf("no gem files found matching pattern: %s", cfg.GemPath),
		}, nil
	}

	// Validate resolved gem paths have .gem extension
	for _, gemFile := range gemFiles {
		if !strings.HasSuffix(gemFile, ".gem") {
			return &plugin.ExecuteResponse{
				Success: false,
				Error:   fmt.Sprintf("resolved path '%s' does not have .gem extension", gemFile),
			}, nil
		}
	}

	if dryRun {
		return &plugin.ExecuteResponse{
			Success: true,
			Message: fmt.Sprintf("Would push %d gem(s) to %s", len(gemFiles), cfg.Host),
			Outputs: map[string]any{
				"host":      cfg.Host,
				"gem_files": gemFiles,
				"has_otp":   cfg.OTP != "",
			},
		}, nil
	}

	// Check for API key
	if cfg.APIKey == "" {
		return &plugin.ExecuteResponse{
			Success: false,
			Error:   "API key is required: set api_key in config or GEM_HOST_API_KEY environment variable",
		}, nil
	}

	// Push each gem file
	pushedGems := make([]string, 0, len(gemFiles))
	for _, gemFile := range gemFiles {
		if err := p.executeGemPush(ctx, cfg, gemFile); err != nil {
			return &plugin.ExecuteResponse{
				Success: false,
				Error:   fmt.Sprintf("failed to push gem '%s': %v", gemFile, err),
				Outputs: map[string]any{
					"pushed_gems": pushedGems,
					"failed_gem":  gemFile,
				},
			}, nil
		}
		pushedGems = append(pushedGems, gemFile)
	}

	return &plugin.ExecuteResponse{
		Success: true,
		Message: fmt.Sprintf("Successfully pushed %d gem(s) to %s", len(pushedGems), cfg.Host),
		Outputs: map[string]any{
			"host":        cfg.Host,
			"pushed_gems": pushedGems,
		},
	}, nil
}

// resolveGemPath resolves a gem path pattern to actual file paths.
func (p *RubyGemsPlugin) resolveGemPath(pattern string, version string) ([]string, error) {
	// Replace version placeholders
	resolvedPattern := strings.ReplaceAll(pattern, "{{version}}", strings.TrimPrefix(version, "v"))

	// Check if it's a glob pattern
	if strings.ContainsAny(resolvedPattern, "*?[]") {
		matches, err := filepath.Glob(resolvedPattern)
		if err != nil {
			return nil, fmt.Errorf("invalid glob pattern: %w", err)
		}
		return matches, nil
	}

	// Single file path
	return []string{resolvedPattern}, nil
}

// executeGemPush runs the gem push command for a single gem file.
func (p *RubyGemsPlugin) executeGemPush(ctx context.Context, cfg *Config, gemFile string) error {
	args := []string{"push", gemFile}

	// Add host flag
	if cfg.Host != "" && cfg.Host != "https://rubygems.org" {
		args = append(args, "--host", cfg.Host)
	}

	// Add OTP flag if provided
	if cfg.OTP != "" {
		args = append(args, "--otp", cfg.OTP)
	}

	// Set API key via environment variable (more secure than command line)
	env := []string{fmt.Sprintf("GEM_HOST_API_KEY=%s", cfg.APIKey)}

	output, err := p.getExecutor().Run(ctx, "gem", args, env)
	if err != nil {
		return fmt.Errorf("%w: %s", err, string(output))
	}

	return nil
}

// parseConfig parses the raw configuration into a Config struct.
func (p *RubyGemsPlugin) parseConfig(raw map[string]any) *Config {
	parser := helpers.NewConfigParser(raw)

	return &Config{
		APIKey:  parser.GetString("api_key", "GEM_HOST_API_KEY", ""),
		Host:    parser.GetString("host", "", "https://rubygems.org"),
		GemPath: parser.GetString("gem_path", "", "pkg/*.gem"),
		OTP:     parser.GetString("otp", "", ""),
	}
}

// Validate validates the plugin configuration.
func (p *RubyGemsPlugin) Validate(_ context.Context, config map[string]any) (*plugin.ValidateResponse, error) {
	vb := helpers.NewValidationBuilder()
	parser := helpers.NewConfigParser(config)

	// Validate host URL
	host := parser.GetString("host", "", "https://rubygems.org")
	if host != "" {
		// Basic URL format validation (runtime will do full SSRF check)
		if !strings.HasPrefix(host, "https://") && !strings.HasPrefix(host, "http://localhost") && !strings.HasPrefix(host, "http://127.0.0.1") {
			vb.AddError("host", "host must use HTTPS protocol (except for localhost)")
		}
	}

	// Validate gem_path pattern if provided
	gemPath := parser.GetString("gem_path", "", "pkg/*.gem")
	if gemPath != "" {
		if err := validateGemPathPattern(gemPath); err != nil {
			vb.AddError("gem_path", err.Error())
		}
	}

	// Validate OTP format if provided
	otp := parser.GetString("otp", "", "")
	if otp != "" {
		if err := validateOTP(otp); err != nil {
			vb.AddError("otp", err.Error())
		}
	}

	// API key is validated at runtime since it might be provided via environment variable
	// at execution time rather than in the configuration.

	return vb.Build(), nil
}
