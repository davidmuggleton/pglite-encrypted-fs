import {
  createCipheriv,
  createDecipheriv,
  createHash,
  pbkdf2Sync,
  randomBytes,
} from 'crypto'

/**
 * Page size: 8192 (Postgres default).
 * Salt: 16 bytes. IV: 12 bytes (AES-GCM). Auth tag: 16 bytes (AES-GCM).
 * KDF iterations: 256 000 (OWASP minimum for PBKDF2-SHA512).
 * File ID: 32-byte random value stored in each file header.
 * File header: [salt (16B)][fileId (32B)] = 48 bytes.
 */
export const PAGE_SIZE = 8192
export const SALT_SIZE = 16
export const IV_SIZE = 12
export const AUTH_TAG_SIZE = 16
export const KDF_ITERATIONS = 256000
export const FILE_ID_SIZE = 32
export const FILE_HEADER_SIZE = SALT_SIZE + FILE_ID_SIZE
export const ENCRYPTED_PAGE_SIZE = PAGE_SIZE + IV_SIZE + AUTH_TAG_SIZE
const ALGORITHM = 'aes-256-gcm'
const KDF_DIGEST = 'sha512'

/** Magic bytes used to verify passphrase correctness on reopen (padded to PAGE_SIZE during use). */
export const VERIFICATION_MAGIC = Buffer.from(
  'PGLITE_ENC\x00\x00\x00\x00\x00\x00',
)

/** Fixed file ID used for the verification token file. */
export const VERIFICATION_FILE_ID = fileIdFromPath('.encryption-verify')

/**
 * Computes a deterministic 32-byte file identifier from a relative path.
 * Used as part of GCM AAD to bind encrypted pages to their file.
 */
export function fileIdFromPath(relativePath: string): Buffer {
  return createHash('sha256').update(relativePath).digest()
}

export interface DerivedKeys {
  encKey: Buffer
}

/**
 * Derives a 256-bit encryption key from a passphrase using PBKDF2-SHA512.
 * @param passphrase The user's password.
 * @param salt A unique 16-byte salt for this vault.
 * @returns The derived encryption key.
 */
export function deriveKeys(passphrase: string, salt: Buffer): DerivedKeys {
  if (salt.length !== SALT_SIZE) throw new Error('Invalid salt length')
  const encKey = pbkdf2Sync(passphrase, salt, KDF_ITERATIONS, 32, KDF_DIGEST)
  return { encKey }
}

/**
 * Generates a cryptographically secure random salt.
 * @returns A 16-byte buffer.
 */
export function randomSalt(): Buffer {
  return randomBytes(SALT_SIZE)
}

/**
 * Encrypts a single 8KB page using AES-256-GCM.
 * Undersized plaintexts are zero-padded to PAGE_SIZE.
 * The file ID and page number are used as AAD to prevent both
 * intra-file page swapping and cross-file page swapping.
 * @param plaintext The page buffer (up to PAGE_SIZE bytes).
 * @param pageNo The page number within the database file.
 * @param keys The derived encryption keys.
 * @param fileId A 32-byte identifier for the file.
 * @returns A buffer containing [IV (12B)][AuthTag (16B)][Ciphertext (8KB)].
 */
export function encryptPage(
  plaintext: Buffer,
  pageNo: number,
  keys: DerivedKeys,
  fileId: Buffer,
): Buffer {
  if (!Number.isInteger(pageNo) || pageNo < 0 || pageNo > 0xffffffff) {
    throw new Error(`Page number out of range: ${pageNo}`)
  }

  if (plaintext.length !== PAGE_SIZE) {
    const padded = Buffer.alloc(PAGE_SIZE)
    plaintext.copy(padded)
    plaintext = padded
  }

  const iv = randomBytes(IV_SIZE)
  const pageNoBuffer = Buffer.alloc(4)
  pageNoBuffer.writeUInt32BE(pageNo)

  const aad = Buffer.concat([fileId, pageNoBuffer])

  const cipher = createCipheriv(ALGORITHM, keys.encKey, iv)
  cipher.setAAD(aad)

  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()])
  const authTag = cipher.getAuthTag()

  return Buffer.concat([iv, authTag, ciphertext])
}

/**
 * Decrypts a single page using AES-256-GCM.
 * Verifies the authentication tag and AAD (file ID + page number).
 * @param encryptedPage The buffer containing the encrypted page data.
 * @param pageNo The page number.
 * @param keys The derived encryption keys.
 * @param fileId A 32-byte identifier for the file.
 * @returns The decrypted 8KB page buffer.
 */
export function decryptPage(
  encryptedPage: Buffer,
  pageNo: number,
  keys: DerivedKeys,
  fileId: Buffer,
): Buffer {
  if (!Number.isInteger(pageNo) || pageNo < 0 || pageNo > 0xffffffff) {
    throw new Error(`Page number out of range: ${pageNo}`)
  }

  if (encryptedPage.length !== ENCRYPTED_PAGE_SIZE) {
    throw new Error(`Encrypted page wrong size for page ${pageNo}`)
  }

  const iv = encryptedPage.subarray(0, IV_SIZE)
  const authTag = encryptedPage.subarray(IV_SIZE, IV_SIZE + AUTH_TAG_SIZE)
  const ciphertext = encryptedPage.subarray(IV_SIZE + AUTH_TAG_SIZE)

  const pageNoBuffer = Buffer.alloc(4)
  pageNoBuffer.writeUInt32BE(pageNo)

  const aad = Buffer.concat([fileId, pageNoBuffer])

  try {
    const decipher = createDecipheriv(ALGORITHM, keys.encKey, iv)
    decipher.setAuthTag(authTag)
    decipher.setAAD(aad)

    return Buffer.concat([decipher.update(ciphertext), decipher.final()])
  } catch (e: unknown) {
    throw Object.assign(
      new Error(
        `Decryption failed for page ${pageNo}: authentication failed.`,
      ),
      { cause: e },
    )
  }
}
