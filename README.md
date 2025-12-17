# RubyGems Plugin for Relicta

Official RubyGems plugin for [Relicta](https://github.com/relicta-tech/relicta) - Publish gems to RubyGems.org (Ruby).

## Installation

```bash
relicta plugin install rubygems
relicta plugin enable rubygems
```

## Configuration

Add to your `release.config.yaml`:

```yaml
plugins:
  - name: rubygems
    enabled: true
    config:
      # Add configuration options here
```

## License

MIT License - see [LICENSE](LICENSE) for details.
