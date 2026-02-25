# secretdetector

Local Secret Scanner - detects exposed secrets and credentials in files.

## Purpose

Scan directories for hardcoded secrets, API keys, passwords, and tokens. Prevents accidental credential exposure.

## Installation

```bash
go build -o secretdetector ./cmd/secretdetector
```

## Usage

```bash
secretdetector <directory>
```

### Examples

```bash
# Scan current directory
secretdetector .

# Scan specific directory
secretdetector /path/to/project

# Scan code directory
secretdetector src/
```

## Output

```
=== SECRET SCAN RESULTS ===

[CRITICAL] PRIVATE_KEY in config/keys.pem:15
  Found: ----BEG*********************KEY----

[WARNING] API_KEY in config/settings.yaml:42
  Found: api_***********************xyz12

[CRITICAL] AWS_KEY in env/.env:8
  Found: AKIA*****************ABC12

Total secrets found: 3
```

## Detected Secret Types

- API_KEY: API keys and tokens
- SECRET_KEY: Secret and private keys
- PASSWORD: Password values
- TOKEN: Authentication tokens
- AWS_KEY: AWS access keys (AKIA...)
- PRIVATE_KEY: Private key files

## Severity Levels

- CRITICAL: High-risk secrets (AWS keys, private keys)
- WARNING: Standard secrets (API keys, passwords, tokens)

## Excluded Directories

- .git
- node_modules
- vendor
- bin
- *.min.js files

## Dependencies

- Go 1.21+
- github.com/fatih/color

## Build and Run

```bash
# Build
go build -o secretdetector ./cmd/secretdetector

# Run
go run ./cmd/secretdetector /path/to/scan
```

## Integration

Use in CI/CD pipelines to prevent secret commits:

```bash
secretdetector src/ && secretdetector config/
```

## License

MIT