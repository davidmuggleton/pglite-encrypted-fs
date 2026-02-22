# pglite-encrypted-fs

[![npm version](https://img.shields.io/npm/v/pglite-encrypted-fs.svg)](https://www.npmjs.com/package/pglite-encrypted-fs)
[![CI](https://github.com/davidmuggleton/pglite-encrypted-fs/actions/workflows/ci.yml/badge.svg)](https://github.com/davidmuggleton/pglite-encrypted-fs/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)

An encrypted virtual filesystem for [PGlite](https://pglite.dev/). Provides transparent AES-256-GCM page-level encryption so your PGlite database files are encrypted at rest.

> **Status:** Alpha. The on-disk format is not yet versioned and may change before 1.0.

## Why this exists

[PGlite](https://pglite.dev/) gives you a full embedded PostgreSQL in Node.js -- SQL, indexes, transactions, extensions like pgvector, all without a server. But out of the box, database files sit **plaintext on disk**.

This package is an encrypted VFS that plugs into PGlite's filesystem layer, encrypting every page as it's written and decrypting as it's read. Your PGlite code stays the same -- you just pass an `EncryptedFS` instance at creation.

## Features

- **AES-256-GCM authenticated encryption** -- page-level encryption with integrity verification on every read
- **PBKDF2-SHA512 key derivation** -- 256K iterations, aligned with [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) guidance
- **Near-zero read overhead** -- decrypted pages are cached in PostgreSQL's buffer pool; subsequent reads hit the cache
- **AAD binding prevents page swapping/replay attacks** -- each page is bound to its file identity and position
- **Passphrase verification on reopen** -- a wrong key is detected immediately, before any data is served
- **Transparent to PGlite extensions** -- pgvector and other extensions work normally on top of the encrypted VFS

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
import { EncryptedFS } from 'pglite-encrypted-fs'

const dataDir = './my-encrypted-db'
const fs = new EncryptedFS(dataDir, 'my-secret-passphrase')
const db = await PGlite.create({ dataDir, fs })

await db.exec('CREATE TABLE users (id SERIAL PRIMARY KEY, name TEXT)')
await db.exec("INSERT INTO users (name) VALUES ('Alice')")
const result = await db.query('SELECT * FROM users')
console.log(result.rows) // [{ id: 1, name: 'Alice' }]

await db.close()
```

## Reopening an Existing Database

Use the same passphrase -- the salt is stored automatically.

```typescript
const fs = new EncryptedFS(dataDir, 'my-secret-passphrase')
const db = await PGlite.create({ dataDir, fs })
// Your data is still there, decrypted transparently
```

If the passphrase is wrong, the constructor throws immediately with `"Invalid passphrase or corrupted encryption keys"`.

## pgvector Example

PGlite extensions work normally on top of the encrypted VFS. Here's pgvector:

```typescript
import { PGlite } from '@electric-sql/pglite'
import { vector } from '@electric-sql/pglite/vector'
import { EncryptedFS } from 'pglite-encrypted-fs'

const dataDir = './my-encrypted-vectors'
const fs = new EncryptedFS(dataDir, process.env.DB_PASSPHRASE!)
const db = await PGlite.create({ dataDir, fs, extensions: { vector } })

await db.exec('CREATE EXTENSION IF NOT EXISTS vector')
await db.exec('CREATE TABLE docs (id serial PRIMARY KEY, embedding vector(3))')
await db.exec("INSERT INTO docs (embedding) VALUES ('[0.1, 0.2, 0.3]')")

const { rows } = await db.query(
  "SELECT * FROM docs ORDER BY embedding <-> '[0.1, 0.2, 0.3]' LIMIT 5"
)
console.log(rows)

await db.close()
fs.destroy()
```

## API Reference

### `new EncryptedFS(dataDir, passphrase, options?)`

Creates an encrypted filesystem instance.

| Parameter | Type | Description |
|-----------|------|-------------|
| `dataDir` | `string` | Path to the database directory on disk |
| `passphrase` | `string` | Your encryption passphrase |
| `options` | `{ debug?: boolean }` | Optional. Enable debug logging with `{ debug: true }` |

The constructor creates the data directory if it does not exist. On first use, it generates a random salt and creates a verification token. On subsequent opens, it reads the salt from the existing verification token and verifies the passphrase is correct.

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

On first initialization, a `.encryption-verify` file is created containing the 16-byte salt followed by a known magic value encrypted with the derived key. On every subsequent open, the salt is read from this file, the key is re-derived, and the magic value is decrypted and checked. A wrong passphrase fails immediately rather than silently serving corrupted data.

### Unencrypted Files

The following PostgreSQL metadata files are left unencrypted because they contain no user data and PostgreSQL requires them in plaintext:

- `.conf` files (configuration)
- `.pid` files (process ID)
- `PG_VERSION`
- `pg_internal.init`
- `postmaster.*`
- `.lock` files
- `replorigin_checkpoint`

## Threat Model

This provides **at-rest encryption** of PGlite/PostgreSQL database files on disk. It protects against offline theft or unauthorized access to the stored files.

**Non-goals:**

- Does not protect against an attacker who can run code in your process
- Data is decrypted in memory during query execution (like any database encryption-at-rest)
- JavaScript runtimes cannot guarantee secure key erasure (`destroy()` is best-effort)
- This package has not been independently audited. If you find a vulnerability, please report it privately via GitHub.

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

Read operations have near-zero overhead because data is decrypted when pages are loaded into PostgreSQL's buffer pool. Subsequent reads hit the cache, so reads are only slow the first time a page is loaded. Write overhead comes from per-page encryption. Run benchmarks yourself with `pnpm run bench`.

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

## FAQ

**Can I rotate the passphrase?**

Not in-place. Export your data with `pg_dump` (or application-level export), create a new encrypted database with the new passphrase, and re-import.

**Can I migrate an existing plaintext PGlite database?**

Same approach -- dump and re-import into a new encrypted database.

**Why not SQLCipher?**

SQLCipher encrypts **SQLite** databases. This package encrypts **PGlite/PostgreSQL** databases. If you're already using PGlite for its PostgreSQL features (extensions, SQL semantics, pgvector), this adds at-rest encryption without changing databases.

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
