package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/cmd/cosign/cli/rekor"
	"github.com/sigstore/cosign/cmd/cosign/cli/sign"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/cosign/attestation"
	"github.com/sigstore/cosign/pkg/types"
	"github.com/sigstore/sigstore/pkg/signature/dsse"
	"github.com/spf13/cobra"
	"golang.org/x/xerrors"
)

func fileDigest(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", xerrors.Errorf("failed to open: %w", err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", xerrors.Errorf("failed to copy: %w", err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func readPredicate(path string) (interface{}, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, xerrors.Errorf("failed to read file: %w", err)
	}

	var predicate interface{}
	if err := json.Unmarshal(data, &predicate); err != nil {
		return nil, xerrors.Errorf("failed to unmarshal json: %w", err)
	}
	return predicate, nil
}

func uploadToRekor(ctx context.Context, sv *sign.SignerVerifier, rekorURL string, signedPayload []byte) error {
	rekorBytes, err := sv.Bytes(ctx)
	if err != nil {
		return xerrors.Errorf("failed to get rekor bytes: %w", err)
	}

	rekorClient, err := rekor.NewClient(rekorURL)
	if err != nil {
		return xerrors.Errorf("failed to create rekor client: %w", err)
	}
	entry, err := cosign.TLogUploadInTotoAttestation(ctx, rekorClient, signedPayload, rekorBytes)
	if err != nil {
		return xerrors.Errorf("failed to upload to tlog: %w", err)
	}
	fmt.Fprintln(os.Stderr, "tlog entry created with index:", *entry.LogIndex)
	return nil
}

func attest(predicateType, predicatePath, blobPath string) error {
	digest, err := fileDigest(blobPath)
	if err != nil {
		return xerrors.Errorf("failed to get blob digest: %w", err)
	}

	predicate, err := readPredicate(predicatePath)
	if err != nil {
		return xerrors.Errorf("failed to read predicate: %w", err)
	}

	st := in_toto.Statement{
		StatementHeader: in_toto.StatementHeader{
			Type:          in_toto.StatementInTotoV01,
			PredicateType: predicateType,
			Subject: []in_toto.Subject{
				{
					Name: blobPath,
					Digest: map[string]string{
						"sha256": digest,
					},
				},
			},
		},
		Predicate: attestation.CosignPredicate{
			Data: predicate,
		},
	}
	payload, err := json.Marshal(st)
	if err != nil {
		return xerrors.Errorf("failed to marshal json: %w", err)
	}

	ctx := context.Background()
	ko := options.KeyOpts{
		FulcioURL:    options.DefaultFulcioURL,
		RekorURL:     options.DefaultRekorURL,
		OIDCIssuer:   options.DefaultOIDCIssuerURL,
		OIDCClientID: "sigstore",

		InsecureSkipFulcioVerify: false,
		SkipConfirmation:         true,
	}

	sv, err := sign.SignerFromKeyOpts(ctx, "", "", ko)
	if err != nil {
		return fmt.Errorf("failed to get signer: %w", err)
	}
	defer sv.Close()

	wrapped := dsse.WrapSigner(sv, types.IntotoPayloadType)

	signedPayload, err := wrapped.SignMessage(bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("failed to sign: %w", err)
	}

	fmt.Println(string(signedPayload))

	err = uploadToRekor(ctx, sv, ko.RekorURL, signedPayload)
	if err != nil {
		return xerrors.Errorf("failed to upload to rekor: %w", err)
	}

	return nil

}

func main() {
	var rootCmd = &cobra.Command{
		Use:   "attest",
		Short: "A Trivy plugin that publish SBOM attestation",
		Example: `  trivy attest --type PREDICATE_TYPE --predicate PREDICATE_PATH BLOB_PATH
  # Publish SBOM attestation
  trivy attest --type cyclonedx --predicate ./sbom.cdx.json ./my-executable`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			rawType, err := cmd.Flags().GetString("type")
			if err != nil {
				return err
			}

			var predicateType string
			switch rawType {
			case "cyclonedx":
				predicateType = in_toto.PredicateCycloneDX
			default:
				return fmt.Errorf("unsupported predicate type")
			}

			predicatePath, err := cmd.Flags().GetString("predicate")
			if err != nil {
				return err
			}

			blobPath := args[0]

			err = attest(predicateType, predicatePath, blobPath)
			if err != nil {
				return err
			}

			return nil
		},
	}

	rootCmd.Flags().StringP("type", "", "", "specify the predicate type(cyclonedx)")
	rootCmd.MarkFlagRequired("type")

	rootCmd.Flags().StringP("predicate", "", "", "specify the predicate file path")
	rootCmd.MarkFlagRequired("predicate")

	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}
