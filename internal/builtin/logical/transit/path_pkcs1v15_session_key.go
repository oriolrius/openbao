// SPDX-License-Identifier: Apache-2.0

package transit

import (
	"context"
	"encoding/base64"
	"errors"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/helper/errutil"
	"github.com/openbao/openbao/sdk/v2/helper/keysutil"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// PKI Manager downstream: RSAES-PKCS1-v1_5 session-key transport for SCEP.
//
// The route is separate from decrypt/, so an ACL policy can grant it to the
// SCEP RA identity alone (for example
// path "transit/session-key/pkcs1v15/scep-ra-*" { capabilities = ["update"] }).
// The key must opt in at creation or import, the caller names the key
// version, and the caller states the expected session-key length.
// The audit broker HMACs the ciphertext and the session key, as for any
// other string field.

const pkcs1v15SessionKeyPathPrefix = "session-key/pkcs1v15/"

func (b *backend) pathPKCS1v15SessionKey() *framework.Path {
	return &framework.Path{
		Pattern: pkcs1v15SessionKeyPathPrefix + framework.GenericNameRegex("name"),

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixTransit,
			OperationVerb:   "decrypt",
			OperationSuffix: "pkcs1v15-session-key",
		},

		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the rsa-3072 key. The key must have allow_pkcs1v15_session_key set.",
			},
			"ciphertext": {
				Type:        framework.TypeString,
				Description: "Base64 (standard) of the raw RSAES-PKCS1-v1_5 encrypted key, exactly the modulus size (384 bytes).",
			},
			"key_version": {
				Type:        framework.TypeInt,
				Description: "Key version to use. Required; the latest version is not implied.",
			},
			"session_key_length": {
				Type:        framework.TypeInt,
				Description: "Expected session-key length in bytes: 16, 24 or 32. Required.",
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathPKCS1v15SessionKeyWrite,
			},
		},

		HelpSynopsis:    pathPKCS1v15SessionKeyHelpSyn,
		HelpDescription: pathPKCS1v15SessionKeyHelpDesc,
	}
}

func (b *backend) pathPKCS1v15SessionKeyWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	for _, field := range []string{"ciphertext", "key_version", "session_key_length"} {
		if _, ok := d.GetOk(field); !ok {
			return logical.ErrorResponse("missing required field %q", field), logical.ErrInvalidRequest
		}
	}
	if _, ok := d.Raw["batch_input"]; ok {
		return logical.ErrorResponse("batch_input is not supported on this path"), logical.ErrInvalidRequest
	}

	version := d.Get("key_version").(int)
	keyLen := d.Get("session_key_length").(int)
	if !keysutil.ValidPKCS1v15SessionKeyLength(keyLen) {
		return logical.ErrorResponse("session_key_length must be one of %v", keysutil.PKCS1v15SessionKeyLengths), logical.ErrInvalidRequest
	}
	ciphertext, err := base64.StdEncoding.DecodeString(d.Get("ciphertext").(string))
	if err != nil || len(ciphertext) == 0 {
		return logical.ErrorResponse("ciphertext must be non-empty standard base64"), logical.ErrInvalidRequest
	}

	p, _, err := b.GetPolicy(ctx, keysutil.PolicyRequest{
		Storage: req.Storage,
		Name:    d.Get("name").(string),
	}, b.GetRandomReader())
	if err != nil {
		return nil, err
	}
	if p == nil {
		return logical.ErrorResponse("encryption key not found"), logical.ErrInvalidRequest
	}
	defer p.Unlock()

	sessionKey, err := p.DecryptPKCS1v15SessionKey(version, ciphertext, keyLen)
	if err != nil {
		var userErr errutil.UserError
		if errors.As(err, &userErr) {
			return logical.ErrorResponse(userErr.Error()), logical.ErrInvalidRequest
		}
		return nil, err
	}

	return &logical.Response{
		Data: map[string]any{
			"session_key": base64.StdEncoding.EncodeToString(sessionKey),
			"key_version": version,
		},
	}, nil
}

// validatePKCS1v15SessionKeyOptIn checks the opt-in on key creation and import.
func validatePKCS1v15SessionKeyOptIn(polReq keysutil.PolicyRequest) *logical.Response {
	if !polReq.AllowPKCS1v15SessionKey {
		return nil
	}
	if polReq.KeyType != keysutil.KeyType_RSA3072 {
		return logical.ErrorResponse("allow_pkcs1v15_session_key requires type rsa-3072")
	}
	if polReq.Derived {
		return logical.ErrorResponse("allow_pkcs1v15_session_key cannot be combined with derived keys")
	}
	return nil
}

const pathPKCS1v15SessionKeyHelpSyn = `Recover an RSAES-PKCS1-v1_5 wrapped session key (SCEP CMS)`

const pathPKCS1v15SessionKeyHelpDesc = `
This path is a PKI Manager downstream addition. It recovers a content-
encryption key that a SCEP client wrapped with RSAES-PKCS1-v1_5 for the
named rsa-3072 key. The key must have allow_pkcs1v15_session_key set when it
was created or imported. The caller supplies the key version and the
expected session-key length (16, 24 or 32 bytes).

The response always contains a session key of the requested length. When
the padding is invalid, the session key is a deterministic value that the
caller cannot tell apart from a real one, so the response never shows
whether the padding was valid. The CMS content decryption that follows
fails in the normal way.
`
