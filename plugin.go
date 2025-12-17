// Package main implements the RubyGems plugin for Relicta.
package main

import (
	"context"
	"fmt"

	"github.com/relicta-tech/relicta-plugin-sdk/helpers"
	"github.com/relicta-tech/relicta-plugin-sdk/plugin"
)

// RubyGemsPlugin implements the Publish gems to RubyGems.org (Ruby) plugin.
type RubyGemsPlugin struct{}

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
			"properties": {}
		}`,
	}
}

// Execute runs the plugin for a given hook.
func (p *RubyGemsPlugin) Execute(ctx context.Context, req plugin.ExecuteRequest) (*plugin.ExecuteResponse, error) {
	switch req.Hook {
	case plugin.HookPostPublish:
		if req.DryRun {
			return &plugin.ExecuteResponse{
				Success: true,
				Message: "Would execute rubygems plugin",
			}, nil
		}
		return &plugin.ExecuteResponse{
			Success: true,
			Message: "RubyGems plugin executed successfully",
		}, nil
	default:
		return &plugin.ExecuteResponse{
			Success: true,
			Message: fmt.Sprintf("Hook %s not handled", req.Hook),
		}, nil
	}
}

// Validate validates the plugin configuration.
func (p *RubyGemsPlugin) Validate(_ context.Context, config map[string]any) (*plugin.ValidateResponse, error) {
	vb := helpers.NewValidationBuilder()
	return vb.Build(), nil
}
