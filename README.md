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
go install github.com/ndrpnt/sops-generic-keyservice@latest
```

## Usage

```sh
$ sops-generic-keyservice serve --help
Start a SOPS-compatible gRPC key service server.
Configure SOPS with: sops --keyservice unix:///tmp/sops.sock

Usage:
  sops-generic-keyservice serve [flags]

Flags:
      --address string        listen address (for tcp) or socket path (for unix) (default "/tmp/sops.sock")
  -h, --help                  help for serve
      --kms-provider string   KMS provider to use (scaleway, ovh, noop)
      --network string        network type (tcp, unix) (default "unix")
```

### Example usage with Scaleway Key Manager

```sh
# Configure Scaleway credentials.
export SCW_ACCESS_KEY=SCWXXXXXXXXXXXXXXXXX
export SCW_SECRET_KEY=11111111-1111-1111-1111-111111111111

# Start the SOPS key service server.
sops-generic-keyservice serve --kms-provider scaleway &

# Configure SOPS.
export SOPS_KMS_ARN="$(echo -n '{"id":"22222222-2222-2222-2222-222222222222","region":"fr-par"}' | base64)"
export SOPS_KEYSERVICE=unix:///tmp/sops.sock

# Create a SOPS-encrypted file.
sops edit example.sops.yaml
```

[ovh-kms]: https://www.ovhcloud.com/en/identity-security-operations/key-management-service
[pkgsite]: https://pkg.go.dev/github.com/ndrpnt/sops-generic-keyservice
[scw-kms]: https://www.scaleway.com/en/key-manager
[sops-key-service]: https://github.com/getsops/sops?tab=readme-ov-file#key-service
