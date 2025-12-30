package keyservice

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"testing"
)

type fakeKMS struct {
	err error
}

func (f *fakeKMS) Encrypt(_ context.Context, keyInfo, plaintext []byte) ([]byte, error) {
	return append(keyInfo, plaintext...), f.err
}

func (f *fakeKMS) Decrypt(_ context.Context, keyInfo, ciphertext []byte) ([]byte, error) {
	return ciphertext[len(keyInfo):], f.err
}

func TestServerEncrypt(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		srv := New(&fakeKMS{})

		keyInfo := []byte(`{"foo": "bar"}`)
		plaintext := []byte("secret-data")
		ciphertext := append(keyInfo, plaintext...)
		req := &EncryptRequest{
			Key: &Key{
				KeyType: &Key_KmsKey{
					KmsKey: &KmsKey{
						Arn: base64.StdEncoding.EncodeToString(keyInfo),
					},
				},
			},
			Plaintext: plaintext,
		}

		gotResp, err := srv.Encrypt(context.Background(), req)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if !bytes.Equal(gotResp.Ciphertext, ciphertext) {
			t.Errorf("invalid resp: got %s, want %s", gotResp.Ciphertext, ciphertext)
		}
	})

	t.Run("kms error", func(t *testing.T) {
		srv := New(&fakeKMS{err: errors.New("some kms error")})
		req := &EncryptRequest{Key: &Key{KeyType: &Key_KmsKey{KmsKey: &KmsKey{}}}}

		_, err := srv.Encrypt(context.Background(), req)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run("invalid arguments", func(t *testing.T) {
		testCases := []struct {
			name string
			req  *EncryptRequest
		}{
			{
				name: "bad key type: PgpKey",
				req:  &EncryptRequest{Key: &Key{KeyType: &Key_PgpKey{}}},
			},
			{
				name: "bad key type: AgeKey",
				req:  &EncryptRequest{Key: &Key{KeyType: &Key_AgeKey{}}},
			},
			{
				name: "bad key type: GcpKmsKey",
				req:  &EncryptRequest{Key: &Key{KeyType: &Key_GcpKmsKey{}}},
			},
			{
				name: "bad key type: AzureKeyvaultKey",
				req:  &EncryptRequest{Key: &Key{KeyType: &Key_AzureKeyvaultKey{}}},
			},
			{
				name: "bad key type: VaultKey",
				req:  &EncryptRequest{Key: &Key{KeyType: &Key_VaultKey{}}},
			},
			{
				name: "missing key type",
				req:  &EncryptRequest{Key: &Key{}},
			},
			{
				name: "bad key info encoding",
				req:  &EncryptRequest{Key: &Key{KeyType: &Key_KmsKey{KmsKey: &KmsKey{Arn: "not base64 encoded"}}}},
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				srv := New(&fakeKMS{})
				_, err := srv.Encrypt(context.Background(), tc.req)
				if err == nil {
					t.Fatal("expected error, got nil")
				}
			})
		}
	})
}

func TestServerDecrypt(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		srv := New(&fakeKMS{})

		keyInfo := []byte(`{"foo": "bar"}`)
		plaintext := []byte("secret-data")
		ciphertext := append(keyInfo, plaintext...)
		req := &DecryptRequest{
			Key: &Key{
				KeyType: &Key_KmsKey{
					KmsKey: &KmsKey{
						Arn: base64.StdEncoding.EncodeToString(keyInfo),
					},
				},
			},
			Ciphertext: ciphertext,
		}

		gotResp, err := srv.Decrypt(context.Background(), req)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if !bytes.Equal(gotResp.Plaintext, plaintext) {
			t.Errorf("invalid resp: got %s, want %s", gotResp.Plaintext, plaintext)
		}
	})

	t.Run("kms error", func(t *testing.T) {
		srv := New(&fakeKMS{err: errors.New("some kms error")})
		req := &DecryptRequest{Key: &Key{KeyType: &Key_KmsKey{KmsKey: &KmsKey{}}}}

		_, err := srv.Decrypt(context.Background(), req)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run("invalid arguments", func(t *testing.T) {
		testCases := []struct {
			name string
			req  *DecryptRequest
		}{
			{
				name: "bad key type: PgpKey",
				req:  &DecryptRequest{Key: &Key{KeyType: &Key_PgpKey{}}},
			},
			{
				name: "bad key type: AgeKey",
				req:  &DecryptRequest{Key: &Key{KeyType: &Key_AgeKey{}}},
			},
			{
				name: "bad key type: GcpKmsKey",
				req:  &DecryptRequest{Key: &Key{KeyType: &Key_GcpKmsKey{}}},
			},
			{
				name: "bad key type: AzureKeyvaultKey",
				req:  &DecryptRequest{Key: &Key{KeyType: &Key_AzureKeyvaultKey{}}},
			},
			{
				name: "bad key type: VaultKey",
				req:  &DecryptRequest{Key: &Key{KeyType: &Key_VaultKey{}}},
			},
			{
				name: "missing key type",
				req:  &DecryptRequest{Key: &Key{}},
			},
			{
				name: "bad key info encoding",
				req:  &DecryptRequest{Key: &Key{KeyType: &Key_KmsKey{KmsKey: &KmsKey{Arn: "not base64 encoded"}}}},
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				srv := New(&fakeKMS{})
				_, err := srv.Decrypt(context.Background(), tc.req)
				if err == nil {
					t.Fatal("expected error, got nil")
				}
			})
		}
	})
}
