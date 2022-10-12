# trivy-plugin-attest
Publish SBOM attestation

## Install

```
$ trivy plugin install github.com/aquasecurity/trivy-plugin-attest
```

## Usage

```
Usage: trivy attest [-h,--help] PREDICATE_TYPE PREDICATE_PATH BLOB_PATH
 A Trivy plugin that publish SBOM attestation.
Examples:
  # Publish SBOM attestation
  trivy attest cyclonedx ./sbom.cdx.json ./my-executable
```
