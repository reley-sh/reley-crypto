# reley-crypto

Open-source E2E encryption libraries for [Reley](https://reley.sh) — bridge your terminal to mobile/web with end-to-end encryption.

## Packages

| Package | Description |
|---------|-------------|
| [`@reley/crypto`](./packages/crypto) | Core cryptographic primitives (X25519, HKDF, XChaCha20-Poly1305, Double Ratchet) |
| [`@reley/protocol`](./packages/protocol) | Wire protocol constants, message types, and envelope encoding |

## Security Architecture

All terminal data between the CLI and viewer is encrypted end-to-end. The relay server **never** sees plaintext.

### Key Exchange
1. Both sides generate ephemeral **X25519** key pairs (via libsodium)
2. **ECDH** shared secret is computed: `crypto_scalarmult(ourSk, theirPk)`
3. **HKDF-SHA256** derives independent send/recv symmetric keys from the shared secret

### Encryption
- **XChaCha20-Poly1305** AEAD cipher for all messages
- 12-byte random nonce per message (zero-padded to 24 bytes for XChaCha20)
- AAD (Additional Authenticated Data) includes protocol version, message type, and counter

### Forward Secrecy
- **Double Ratchet** protocol: each message derives a new chain key
- Compromising one message key does not reveal past or future messages
- Key rotation signal every 50 messages

### Replay Protection
- Monotonically increasing counter per direction
- Messages with counter <= max received counter are rejected

### MITM Detection
- **Fingerprint verification**: Blake2b hash of sorted public keys
- Users can compare fingerprints out-of-band to verify no man-in-the-middle

## Development

```bash
pnpm install
pnpm build
pnpm test
```

## License

MIT
