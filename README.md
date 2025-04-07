# Pseudonyms

Repository to play with crypto and encoding to create pseudonyms

Uses AES-GCM for encrypting tokens

Uses AES-GCM-SIV for deterministic encryption of pseudonyms

Uses protobuf for serializing data

Run the following command to generate protobuf file:

```terminal
protoc --go_out=paths=source_relative:. proto/messages.proto                                                                                                                                     ─╯
```

## Usage

Execute the following command:

```shell
go run main.go
```

This will start the server on `http://0.0.0.0:8080`.

## Client

A [Bruno Client](https://docs.usebruno.com/introduction/what-is-bruno) is available in the `client` folder.

## Project Structure

```plaintext
.
├── README.md This file
├── client/ Client with bruno config to test the API
├── crypto/ Crypto functions to encrypt/decrypt tokens and pseudonyms using AES-GCM
├── proto/ Protobuf file to define the datamodel
├── domain/ Domain logic to create tokens and pseudonyms in the protobuf format
├── api/ Api files
│   ├── spec.go OpenAPI spec file
│   ├── generate.go Generated AIP from the spec
│   ├── impl.go Implementation of the API
└── main.go Main file to start the server
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
