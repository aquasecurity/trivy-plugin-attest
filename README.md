# trivy-plugin-attest
Publish SBOM attestation

## Install

```
$ trivy plugin install github.com/aquasecurity/trivy-plugin-attest
```

> An important note about the public instance of the Rekor maintained by the Sigstore team is that the attestation size is limited to 100KB. If you are using the public instance, please make sure that your SBOM is smaller than 100KB.
> To get more detail, please refer to the Rekor project's     [documentation](https://github.com/sigstore/rekor#public-instance).

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
