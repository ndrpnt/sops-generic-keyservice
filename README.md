# `sops-generic-keyservice`

A proof of concept [SOPS key service server][sops-key-service]
that enables integration with custom key management systems.
This project allows you to use SOPS with KMS providers that aren't natively supported,
such as [Scaleway Key Manager][scw-kms] and [OVH Key Management Service][ovh-kms].

## Architecture

See the [individual package documentation][pkgsite] for more information.

```txt
       ┌────────────┐
       │    SOPS    │
       │  (client)  │
       └─────┬──────┘
             │ gRPC
             │ (Unix socket or TCP)
             ▼
┌──────────────────────────────┐
│   sops-generic-keyservice    │
│       (this Project)         │
│                              │
│  ┌────────────────────┐      │
│  │ Key Service Server │      │
│  └─────────┬──────────┘      │
│            │ generickms.KMS  │
│            │ interface       │
│            ▼                 │
│  ┌───────────────────┐       │
│  │ Provider-specific │       │
│  │ implementation    │       │
│  └─────────┬─────────┘       │
└────────────┼─────────────────┘
             │ HTTPS API
             ▼
 ┌────────────────────────┐
 │ External KMS provider  │
 │ (Scaleway Key Manager, │
 │     OVH KMS, etc.)     │
 └────────────────────────┘
```

## Installation

```sh
go install github.com/ndrpnt/sops-generic-keyservice/...@latest
```

## Usage

```sh
$ sops-generic-keyservice serve --help
Start a SOPS-compatible gRPC key service server.

When sops-generic-keyservice runs in daemon mode,
it prints the shell commands required to set its environment variables,
which in turn can be evaluated in the calling shell.

For example running "eval $(sops-generic-keyservice serve --kms-provider noop -d)"
configures SOPS to use the keyservice by setting SOPS_KEYSERVICE.

Usage:
  sops-generic-keyservice serve [flags]

Flags:
      --address string        listen address (for tcp) or socket path (for unix) (defaults to a random port on localhost for tcp, or a temporary file for unix)
  -d, --daemon                run in daemon mode
  -h, --help                  help for serve
      --kms-provider string   KMS provider to use (scaleway, ovh, noop)
      --network string        network type (tcp, unix) (default "unix")

Global Flags:
  -q, --quiet count     decrease verbosity
  -v, --verbose count   increase verbosity
```

### Example usage with Scaleway Key Manager

```sh
# Configure Scaleway credentials.
export SCW_ACCESS_KEY=SCWXXXXXXXXXXXXXXXXX
export SCW_SECRET_KEY=11111111-1111-1111-1111-111111111111

# Start the SOPS key service server and configure SOPS to use it.
eval $(sops-generic-keyservice serve --kms-provider scaleway -d)

# Create a SOPS-encrypted file, specifying the key to use.
sops edit --kms $(echo -n '{"id":"22222222-2222-2222-2222-222222222222","region":"fr-par"}' | base64) example.sops.yaml

# Stop the SOPS key service server.
eval $(sops-generic-keyservice kill)
```

### Example usage with OVH KMS

```sh
# Configure OVH KMS credentials.
export OKMS_CLIENT_CERT_FILE=cert.pem
export OKMS_CLIENT_KEY_FILE=key.pem

# Start the SOPS key service server and configure SOPS to use it.
eval $(sops-generic-keyservice serve --kms-provider ovh -d)

# Create a SOPS-encrypted file, specifying the key to use.
sops edit --kms $(echo -n '{"okms_id":"11111111-1111-1111-1111-111111111111","key_id":"22222222-2222-2222-2222-222222222222","endpoint":"https://eu-west-par.okms.ovh.net"}' | base64) example.sops.yaml

# Stop the SOPS key service server.
eval $(sops-generic-keyservice kill)
```

[ovh-kms]: https://www.ovhcloud.com/en/identity-security-operations/key-management-service
[pkgsite]: https://pkg.go.dev/github.com/ndrpnt/sops-generic-keyservice
[scw-kms]: https://www.scaleway.com/en/key-manager
[sops-key-service]: https://github.com/getsops/sops?tab=readme-ov-file#key-service
