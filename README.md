# Pseudonyms

Repository to play with crypto and encoding to create pseudonyms

Uses AES-GCM for encrypting tokens

Uses AES-GCM-SIV for deterministic encryption of pseudonyms

Uses Ristretto elliptic curves for blind signature operations

Uses protobuf for serializing data

Run the following command to generate protobuf file:

```terminal
protoc --go_out=paths=source_relative:. proto/messages.proto
```

## Privacy-Preserving Pseudonym Exchange

This service supports a blinding protocol that allows two parties to exchange pseudonyms without the central service learning the actual identifiers (BSN). The flow works as follows:

1. **Initiator** blinds their BSN and sends the blinded value to the service
2. **Service** evaluates the blinded value with an organization-specific key and encrypts it for the receiver
3. **Receiver** decrypts and unblinds to get their organization-specific pseudonym
4. **Receiver** can optionally recover the original BSN by blinding the pseudonym and sending it back to the service for unevaluation

The service never sees the actual BSN or the final pseudonym - only blinded values.

## Setup

### Generate Organization Keys

Before running the server, generate RSA key pairs for each organization:

```shell
./scripts/generate-keys.sh <org-id> [keys-dir]

# Example:
./scripts/generate-keys.sh hospital-b ./keys
```

This creates:
- `./keys/hospital-b.key` - Private key (chmod 600)
- `./keys/hospital-b.pub` - Public key (chmod 644)

### Start the Server

```shell
go build -o server .
./server -keys-dir=./keys
```

The server starts on `http://0.0.0.0:8082`.

## Client Usage

Build the client:

```shell
go build -o client-bin ./client
```

### Initiator Mode

The initiator blinds a BSN and requests a token for a receiver organization:

```shell
./client-bin -mode=initiator -bsn="bsn:123456789" -receiver-org=hospital-b
```

Output:
```
=== Initiator: Creating pseudonym for Receiver ===

1. Blinded BSN identifier
   Blind (keep secret): X493PisV0QbylnP9okwkwjIFDyMrMi9eGzryBCVgcAs=
   Blinded element: dkkugccc5JJ1BU6OLlbGcqYaK8xhfxbrF5yBV8HfTmg=

2. Requesting token from service for receiver: hospital-b
   Encrypted token received: unKmHll1oTYy...

=== Output for Receiver ===
Token: unKmHll1oTYy...
Blind: X493PisV0QbylnP9okwkwjIFDyMrMi9eGzryBCVgcAs=

Initiator should send both token and blind to Receiver via secure channel.
```

The initiator sends both the **token** and **blind** to the receiver through a secure channel.

### Receiver Mode

The receiver decrypts the token using their private key and recovers the pseudonym (and optionally the original BSN):

```shell
./client-bin -mode=receiver \
  -org=hospital-b \
  -keys-dir=./keys \
  -receiver-org=hospital-b \
  -token="<token from initiator>" \
  -blind="<blind from initiator>"
```

Output:
```
=== Receiver: Recovering Pseudonym ===

1. Loading private key for organization: hospital-b
   Private key loaded successfully

2. Decrypting and unblinding token
   Pseudonym recovered: qkJaeSHLcvXY2Tc4FHl/Z+tuAihm3pBrhNywr0JoGEU=

3. Recovering original BSN from pseudonym
   Blinded pseudonym: VM9JNx7tsO7BNvZ/L6ozKql2Q9LJNuMFZBKluI52u3M=

4. Calling ExchangeIdentifier to unevaluate blinded pseudonym
   Blinded BSN received: NMzLnt8yEZw0U8B8eBM3bLJmARZH9fXw+3Jzh0ANUE4=

5. Unblinding to recover original BSN
   Recovered BSN: bsn:123456789

=== Receiver Flow Complete ===
```

### Client Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-mode` | `initiator` | Mode: `initiator` or `receiver` |
| `-bsn` | `bsn:1234567890` | BSN identifier (initiator mode) |
| `-receiver-org` | `hospital-b` | Receiver organization |
| `-token` | | Encrypted token (receiver mode) |
| `-blind` | | Blind value (receiver mode) |
| `-org` | | Organization ID for private key lookup (receiver mode) |
| `-keys-dir` | `./keys` | Directory containing organization key files |
| `-server` | `http://localhost:8082` | Server URL |

## Bruno Client

A [Bruno Client](https://docs.usebruno.com/introduction/what-is-bruno) is also available in the `client` folder for testing the API directly.

## Project Structure

```plaintext
.
├── README.md           This file
├── main.go             Main file to start the server
├── api/                API files
│   ├── spec.yaml       OpenAPI spec file
│   ├── generate.go     Generated API from the spec
│   └── impl.go         Implementation of the API
├── client/             CLI client for blinding operations
│   ├── client.go       Client implementation (initiator/receiver modes)
│   └── api/            Generated API client
├── crypto/             Crypto functions
│   ├── aesgcm.go       AES-GCM encryption/decryption
│   ├── groups.go       Ristretto elliptic curve operations (blinding)
│   └── keys.go         RSA key loading from filesystem
├── domain/             Domain logic
│   └── token.go        Token and pseudonym creation/decryption
├── proto/              Protobuf definitions
│   └── messages.proto  Datamodel definitions
├── scripts/            Utility scripts
│   └── generate-keys.sh  Generate RSA key pairs for organizations
└── keys/               Organization keys (not in repo)
    ├── {org-id}.key    Private key (PEM format)
    └── {org-id}.pub    Public key (PEM format)
```

## Example token en pseudonym values:

### Token:

```
aGVhZGVyOnt9IG5vbmNlOiJceGQwSSdceGZjKFx4MTQkXHhkOWd7XHhkZmUiIGNpcGhlcnRleHQ6Ilx4ZDNYXHgwY1x4YzFceGUyXHhlMmtYXHhhYlx4OWZ+XHg4M1x4ZTFqXHhhNCNceGFlXHgxYW1ceDg3XHhjYWZceGIwXHgxYVx4Y2VceGRkPDRceGU3XHgwY1x4MDNceDFkXHgwOFx4ZjFceDg3e1x4YWJceDExXHgwZlx4MWV2XHhiZHZceGJkTVx4YThMKVwidVtjalx4ODBceGUzXHg5NFx4YzUlaVx4OTlceGZkXHgxMlx4YzImIg==
```

### Decrypted Token:

```
subject:"123456789" issuer:"222123456" audience:"444123456" expiration:1737041089 issued_at:1737037489 scopes:TREATMENT
```

### Pseudonym:

```
aGVhZGVyOntjb250ZW50X3R5cGU6UFNFVURPTllNfSBub25jZToiXHhhZFx4ZGRyPlx4ZmNceDljXHgxYlx4YmVZTVx4YzlaIiBjaXBoZXJ0ZXh0OiJceDE22ZN8bDlSXCJceGNkXHhmYX5ceGRkXHhjY1x4MDFceGFiXHhkOXpMXHg4OVx4YjBfXHhiZnlWeFx4YzBSXHhmY1xuJytceDEyXHg4NVx4ZDBeXHhiZVx4MThceGEzZHgi
```

### Decrypted Pseudonym:

```
subject:"123456789" audience:"444123456" version:1
```

## Datamodel

See the [protobuf file](proto/messages.proto) for the datamodel.
