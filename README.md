# Pseudonyms

Repository to play with crypto and encoding to create pseudonyms

Uses AES-GCM for encrypting tokens

Uses AES-GCM-SIV for deterministic encryption of pseudonyms

Uses protobuf for serializing data

Run the following command to generate protobuf file:

```
protoc --go_out=paths=source_relative:. proto/messages.proto                                                                                                                                     ─╯

```
