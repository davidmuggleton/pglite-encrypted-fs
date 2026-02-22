# pglite-encrypted-fs

[![npm version](https://img.shields.io/npm/v/pglite-encrypted-fs.svg)](https://www.npmjs.com/package/pglite-encrypted-fs)
[![CI](https://github.com/davidmuggleton/pglite-encrypted-fs/actions/workflows/ci.yml/badge.svg)](https://github.com/davidmuggleton/pglite-encrypted-fs/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)

Transparent AES-256-GCM page-level encryption for PGlite PostgreSQL databases.

## Features

- **AES-256-GCM authenticated encryption** -- page-level encryption with integrity verification on every read
- **PBKDF2-SHA512 key derivation** -- 256K iterations, compliant with OWASP recommendations
- **Near-zero read overhead** -- decrypted pages are cached in PostgreSQL's buffer pool; subsequent reads hit the cache
- **AAD binding prevents page swapping/replay attacks** -- each page is bound to its file identity and position
- **Passphrase verification on reopen** -- a wrong key is detected immediately, before any data is served
- **Works with PGlite extensions** -- pgvector, and any other extension supported by PGlite

## Install

`pglite-encrypted-fs` requires `@electric-sql/pglite` as a peer dependency.

```bash
# pnpm
pnpm add pglite-encrypted-fs @electric-sql/pglite

# npm
npm install pglite-encrypted-fs @electric-sql/pglite

# yarn
yarn add pglite-encrypted-fs @electric-sql/pglite
```

## Quick Start

```typescript
import { PGlite } from '@electric-sql/pglite'
import { EncryptedFS, deriveKeys, randomSalt } from 'pglite-encrypted-fs'

const dataDir = './my-encrypted-db'
const passphrase = 'my-secret-passphrase'

// First time: generate a new salt and derive keys
const salt = randomSalt()
const keys = deriveKeys(passphrase, salt)

// Create the encrypted filesystem and pass it to PGlite
const fs = new EncryptedFS(dataDir, keys, salt)
const db = await PGlite.create({ dataDir, fs })

// Use it like a normal PGlite database
await db.exec('CREATE TABLE users (id SERIAL PRIMARY KEY, name TEXT)')
await db.exec("INSERT INTO users (name) VALUES ('Alice')")
const result = await db.query('SELECT * FROM users')
console.log(result.rows) // [{ id: 1, name: 'Alice' }]

await db.close()

// IMPORTANT: Store the salt alongside your database path.
// You'll need it to reopen the database later.
```

## Reopening an Existing Database

The salt is required to reopen a database. Store it alongside your database path -- for example, in a config file or as a hex-encoded string in your application's settings.

```typescript
// To reopen, use the same salt and passphrase
const keys = deriveKeys(passphrase, savedSalt)
const fs = new EncryptedFS(dataDir, keys, savedSalt)
const db = await PGlite.create({ dataDir, fs })
// Your data is still there, decrypted transparently
```

If the passphrase is wrong, the `EncryptedFS` constructor throws immediately with `"Invalid passphrase or corrupted encryption keys"`.

## API Reference

### `EncryptedFS(dataDir, keys, salt, options?)`

Creates an encrypted filesystem instance.

| Parameter | Type | Description |
|-----------|------|-------------|
| `dataDir` | `string` | Path to the database directory on disk |
| `keys` | `DerivedKeys` | Encryption keys returned by `deriveKeys()` |
| `salt` | `Buffer` | The 16-byte salt used during key derivation |
| `options` | `{ debug?: boolean }` | Optional. Enable debug logging with `{ debug: true }` |

The constructor creates the data directory if it does not exist, and verifies the passphrase against an existing database (or creates the verification token for a new one).

### `deriveKeys(passphrase, salt)`

Derives a 256-bit encryption key from a passphrase using PBKDF2-SHA512 with 256,000 iterations.

| Parameter | Type | Description |
|-----------|------|-------------|
| `passphrase` | `string` | The user's password or passphrase |
| `salt` | `Buffer` | A 16-byte salt (from `randomSalt()` or stored) |

Returns `{ encKey: Buffer }`. Takes approximately 48ms on modern hardware.

### `randomSalt()`

Returns a 16-byte cryptographically random `Buffer` suitable for use with `deriveKeys()`.

### `EncryptedFS.destroy()`

Zeros the encryption key and salt from memory. Call this after closing PGlite to reduce the window of key exposure in heap dumps. Note that JavaScript's garbage collector may have already copied the data, so complete erasure is not guaranteed.

### Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `PAGE_SIZE` | `8192` | PostgreSQL page size (8KB) |
| `SALT_SIZE` | `16` | Salt length in bytes |
| `FILE_HEADER_SIZE` | `48` | File header: 16B salt + 32B file ID |
| `KDF_ITERATIONS` | `256000` | PBKDF2 iteration count |

## Security Design

### Algorithm

AES-256-GCM with a random 12-byte IV generated per page write. The authentication tag (16 bytes) ensures both confidentiality and integrity.

### Page Model

Each 8KB plaintext page becomes 8,220 bytes on disk:

```
[IV (12B)][Auth Tag (16B)][Ciphertext (8192B)]
```

### File Layout

Every encrypted file on disk has this structure:

```
[Header (48B)][Encrypted Page 0][Encrypted Page 1][...]

Header = [Salt (16B)][File ID (32B)]
```

### AAD (Additional Authenticated Data)

Each page's GCM authentication tag covers:

```
AAD = [File ID (32B)][Page Number (4B)]
```

This prevents two classes of attack:
- **Intra-file page swapping** -- moving page 5 to page 3's slot within the same file is detected
- **Cross-file page swapping** -- copying a page from one file into another file is detected

### File IDs

Each file receives a random 32-byte identifier stored in its header. Because file IDs are not derived from the file path, encrypted files survive renames without breaking authentication.

### Passphrase Verification

On first initialization, a `.encryption-verify` file is created containing a known magic value encrypted with the derived key. On every subsequent open, this file is decrypted and checked. A wrong passphrase fails immediately rather than silently serving corrupted data.

### Unencrypted Files

The following PostgreSQL metadata files are left unencrypted because they contain no user data and PostgreSQL requires them in plaintext:

- `.conf` files (configuration)
- `.pid` files (process ID)
- `PG_VERSION`
- `pg_internal.init`
- `postmaster.*`
- `.lock` files
- `replorigin_checkpoint`

## Performance

Benchmarks measured on Node.js (see `pnpm run bench` for your own results):

| Operation | Plain | Encrypted | Overhead |
|-----------|-------|-----------|----------|
| Insert 100 rows | 11.2ms | 13.6ms | +22% |
| Bulk insert 1,000 rows | 5.5ms | 10.5ms | +93% |
| Select 1,000 rows | 0.55ms | 0.54ms | ~0% |
| Select with index | 0.090ms | 0.092ms | ~0% |
| Aggregate (COUNT/SUM) | 0.100ms | 0.098ms | ~0% |
| Mixed CRUD cycle | 0.42ms | 0.48ms | +15% |
| Fresh database init | 531ms | 835ms | +57% |
| Database reopen | 36ms | 86ms | +138% |
| Single page encrypt | -- | 5.4us | -- |
| Single page decrypt | -- | 3.9us | -- |
| Key derivation (PBKDF2) | -- | 48ms | -- |

Read operations have near-zero overhead because data is decrypted when pages are loaded into PostgreSQL's buffer pool. Subsequent reads hit the cache. Write overhead comes from per-page encryption. Run benchmarks yourself with `pnpm run bench`.

## Platform Support

| Platform | Supported |
|----------|-----------|
| Node.js (>=20) | Yes |
| Bun | Yes (untested) |
| Deno | No |
| Chrome | No |
| Safari | No |
| Firefox | No |

This package uses Node.js `crypto` and `fs` modules and is not compatible with browser environments.

## Contributing

```bash
git clone https://github.com/davidmuggleton/pglite-encrypted-fs.git
cd pglite-encrypted-fs
pnpm install
pnpm test
pnpm run bench
```

## License

MIT -- see [LICENSE](./LICENSE).
