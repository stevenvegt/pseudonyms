#!/bin/bash
# Generate RSA key pair for an organization
#
# Usage: ./generate-keys.sh <org-id> [keys-dir]
# Example: ./generate-keys.sh hospital-b ./keys
#
# Creates:
#   {keys-dir}/{org-id}.key - Private key (chmod 600)
#   {keys-dir}/{org-id}.pub - Public key (chmod 644)

set -e

if [ -z "$1" ]; then
    echo "Usage: $0 <org-id> [keys-dir]"
    echo "Example: $0 hospital-b ./keys"
    exit 1
fi

ORG_ID="$1"
KEYS_DIR="${2:-./keys}"

mkdir -p "$KEYS_DIR"

PRIVATE_KEY="$KEYS_DIR/$ORG_ID.key"
PUBLIC_KEY="$KEYS_DIR/$ORG_ID.pub"

# Generate 2048-bit RSA private key
openssl genrsa -out "$PRIVATE_KEY" 2048 2>/dev/null

# Extract public key
openssl rsa -in "$PRIVATE_KEY" -pubout -out "$PUBLIC_KEY" 2>/dev/null

# Set permissions
chmod 600 "$PRIVATE_KEY"
chmod 644 "$PUBLIC_KEY"

echo "Generated keys for organization: $ORG_ID"
echo "  Private key: $PRIVATE_KEY"
echo "  Public key:  $PUBLIC_KEY"
