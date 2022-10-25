# trivy-plugin-attest
Publish SBOM attestation

## Install

```
$ trivy plugin install github.com/aquasecurity/trivy-plugin-attest
```

## Usage

```
A Trivy plugin that publish SBOM attestation

Usage:
  attest [flags]

Examples:
  trivy attest --type PREDICATE_TYPE --predicate PREDICATE_PATH BLOB_PATH
  # Publish SBOM attestation
  trivy attest --type cyclonedx --predicate ./sbom.cdx.json ./my-executable

Flags:
  -h, --help               help for attest
      --predicate string   specify the predicate file path
      --type string        specify the predicate type(cyclonedx)
```
