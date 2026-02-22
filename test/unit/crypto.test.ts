import { describe, it, expect } from 'vitest'
import {
  deriveKeys,
  randomSalt,
  encryptPage,
  decryptPage,
  fileIdFromPath,
  PAGE_SIZE,
  SALT_SIZE,
  IV_SIZE,
  AUTH_TAG_SIZE,
  ENCRYPTED_PAGE_SIZE,
  KDF_ITERATIONS,
} from '../../src/crypto.js'

const TEST_FILE_ID = fileIdFromPath('test/file')

describe('crypto', () => {
  describe('key derivation', () => {
    it('derives stable keys for same password and salt', () => {
      const salt = randomSalt()
      const keys1 = deriveKeys('test-password', salt)
      const keys2 = deriveKeys('test-password', salt)
      expect(keys1.encKey.equals(keys2.encKey)).toBe(true)
    })

    it('derives different keys for different passwords', () => {
      const salt = randomSalt()
      const keys1 = deriveKeys('password1', salt)
      const keys2 = deriveKeys('password2', salt)
      expect(keys1.encKey.equals(keys2.encKey)).toBe(false)
    })

    it('derives different keys for different salts', () => {
      const keys1 = deriveKeys('same-password', randomSalt())
      const keys2 = deriveKeys('same-password', randomSalt())
      expect(keys1.encKey.equals(keys2.encKey)).toBe(false)
    })

    it('produces 32-byte (256-bit) encryption key', () => {
      const keys = deriveKeys('password', randomSalt())
      expect(keys.encKey.length).toBe(32)
    })

    it('requires exactly 16-byte salt', () => {
      expect(() => deriveKeys('password', Buffer.alloc(15))).toThrow(
        'Invalid salt length',
      )
      expect(() => deriveKeys('password', Buffer.alloc(17))).toThrow(
        'Invalid salt length',
      )
      expect(() =>
        deriveKeys('password', Buffer.alloc(SALT_SIZE)),
      ).not.toThrow()
    })

    it('handles empty passphrase', () => {
      const keys = deriveKeys('', randomSalt())
      expect(keys.encKey.length).toBe(32)
    })

    it('handles unicode passphrase', () => {
      const keys = deriveKeys('\u{1F512}\u{1F510}encryption', randomSalt())
      expect(keys.encKey.length).toBe(32)
    })

    it('handles very long passphrase', () => {
      const longPassword = 'a'.repeat(10000)
      const keys = deriveKeys(longPassword, randomSalt())
      expect(keys.encKey.length).toBe(32)
    })

    it('uses at least 256,000 KDF iterations (OWASP guidance)', () => {
      expect(KDF_ITERATIONS).toBeGreaterThanOrEqual(256000)
    })
  })

  describe('salt generation', () => {
    it('generates 16-byte salt', () => {
      const salt = randomSalt()
      expect(salt.length).toBe(SALT_SIZE)
    })

    it('generates unique salts', () => {
      const salt1 = randomSalt()
      const salt2 = randomSalt()
      expect(salt1.equals(salt2)).toBe(false)
    })
  })

  describe('encryption/decryption', () => {
    it('roundtrips a full page', () => {
      const salt = randomSalt()
      const keys = deriveKeys('secret', salt)
      const plaintext = Buffer.alloc(PAGE_SIZE)
      plaintext.write('hello world', 0, 'utf8')

      const encrypted = encryptPage(plaintext, 0, keys, TEST_FILE_ID)
      const decrypted = decryptPage(encrypted, 0, keys, TEST_FILE_ID)

      expect(decrypted.equals(plaintext)).toBe(true)
    })

    it('roundtrips a smaller-than-page buffer (pads to PAGE_SIZE)', () => {
      const salt = randomSalt()
      const keys = deriveKeys('secret', salt)
      const smallData = Buffer.from('small data')

      const encrypted = encryptPage(smallData, 0, keys, TEST_FILE_ID)
      const decrypted = decryptPage(encrypted, 0, keys, TEST_FILE_ID)

      expect(decrypted.length).toBe(PAGE_SIZE)
      expect(decrypted.subarray(0, smallData.length).equals(smallData)).toBe(
        true,
      )
      expect(decrypted.subarray(smallData.length).every((b) => b === 0)).toBe(
        true,
      )
    })

    it('produces encrypted output of exactly ENCRYPTED_PAGE_SIZE bytes', () => {
      const keys = deriveKeys('password', randomSalt())
      const plaintext = Buffer.alloc(PAGE_SIZE, 0x42)
      const encrypted = encryptPage(plaintext, 0, keys, TEST_FILE_ID)
      expect(encrypted.length).toBe(ENCRYPTED_PAGE_SIZE)
      expect(ENCRYPTED_PAGE_SIZE).toBe(IV_SIZE + AUTH_TAG_SIZE + PAGE_SIZE)
    })

    it('generates unique IV for each encryption', () => {
      const keys = deriveKeys('password', randomSalt())
      const plaintext = Buffer.alloc(PAGE_SIZE, 0x42)

      const encrypted1 = encryptPage(plaintext, 0, keys, TEST_FILE_ID)
      const encrypted2 = encryptPage(plaintext, 0, keys, TEST_FILE_ID)

      const iv1 = encrypted1.subarray(0, IV_SIZE)
      const iv2 = encrypted2.subarray(0, IV_SIZE)
      expect(iv1.equals(iv2)).toBe(false)
    })

    it('produces different ciphertext for same plaintext (due to unique IV)', () => {
      const keys = deriveKeys('password', randomSalt())
      const plaintext = Buffer.alloc(PAGE_SIZE, 0x42)

      const encrypted1 = encryptPage(plaintext, 0, keys, TEST_FILE_ID)
      const encrypted2 = encryptPage(plaintext, 0, keys, TEST_FILE_ID)

      expect(encrypted1.equals(encrypted2)).toBe(false)
    })

    it('handles page number 0', () => {
      const keys = deriveKeys('password', randomSalt())
      const plaintext = Buffer.alloc(PAGE_SIZE, 0xab)

      const encrypted = encryptPage(plaintext, 0, keys, TEST_FILE_ID)
      const decrypted = decryptPage(encrypted, 0, keys, TEST_FILE_ID)
      expect(decrypted.equals(plaintext)).toBe(true)
    })

    it('handles maximum page number (UInt32 max)', () => {
      const keys = deriveKeys('password', randomSalt())
      const plaintext = Buffer.alloc(PAGE_SIZE, 0xcd)
      const maxPageNo = 0xffffffff

      const encrypted = encryptPage(plaintext, maxPageNo, keys, TEST_FILE_ID)
      const decrypted = decryptPage(encrypted, maxPageNo, keys, TEST_FILE_ID)
      expect(decrypted.equals(plaintext)).toBe(true)
    })
  })

  describe('tamper detection', () => {
    it('rejects decryption when auth tag is modified', () => {
      const keys = deriveKeys('password', randomSalt())
      const plaintext = Buffer.alloc(PAGE_SIZE, 0xab)
      const encrypted = encryptPage(plaintext, 0, keys, TEST_FILE_ID)

      encrypted[IV_SIZE] ^= 0xff

      expect(() => decryptPage(encrypted, 0, keys, TEST_FILE_ID)).toThrow(
        /Decryption failed/,
      )
    })

    it('rejects single-bit auth tag modification', () => {
      const keys = deriveKeys('password', randomSalt())
      const plaintext = Buffer.alloc(PAGE_SIZE, 0xab)
      const encrypted = encryptPage(plaintext, 0, keys, TEST_FILE_ID)

      encrypted[IV_SIZE + 5] ^= 0x01

      expect(() => decryptPage(encrypted, 0, keys, TEST_FILE_ID)).toThrow(
        /Decryption failed/,
      )
    })

    it('rejects decryption when IV is modified', () => {
      const keys = deriveKeys('password', randomSalt())
      const plaintext = Buffer.alloc(PAGE_SIZE, 0xab)
      const encrypted = encryptPage(plaintext, 0, keys, TEST_FILE_ID)

      encrypted[0] ^= 0xff

      expect(() => decryptPage(encrypted, 0, keys, TEST_FILE_ID)).toThrow(
        /Decryption failed/,
      )
    })

    it('rejects decryption when ciphertext is modified', () => {
      const keys = deriveKeys('password', randomSalt())
      const plaintext = Buffer.alloc(PAGE_SIZE, 0xab)
      const encrypted = encryptPage(plaintext, 0, keys, TEST_FILE_ID)

      encrypted[IV_SIZE + AUTH_TAG_SIZE] ^= 0xff

      expect(() => decryptPage(encrypted, 0, keys, TEST_FILE_ID)).toThrow(
        /Decryption failed/,
      )
    })

    it('rejects single-bit ciphertext modification', () => {
      const keys = deriveKeys('password', randomSalt())
      const plaintext = Buffer.alloc(PAGE_SIZE, 0xab)
      const encrypted = encryptPage(plaintext, 0, keys, TEST_FILE_ID)

      encrypted[IV_SIZE + AUTH_TAG_SIZE + 100] ^= 0x01

      expect(() => decryptPage(encrypted, 0, keys, TEST_FILE_ID)).toThrow(
        /Decryption failed/,
      )
    })

    it('rejects decryption with wrong page number (AAD mismatch)', () => {
      const keys = deriveKeys('password', randomSalt())
      const plaintext = Buffer.alloc(PAGE_SIZE, 0xcd)

      const encrypted = encryptPage(plaintext, 5, keys, TEST_FILE_ID)
      expect(() => decryptPage(encrypted, 6, keys, TEST_FILE_ID)).toThrow(
        /Decryption failed/,
      )
    })

    it('prevents page swapping attack', () => {
      const keys = deriveKeys('password', randomSalt())

      const content = Buffer.alloc(PAGE_SIZE, 0x00)
      const page0 = encryptPage(content, 0, keys, TEST_FILE_ID)
      const page1 = encryptPage(content, 1, keys, TEST_FILE_ID)

      expect(() => decryptPage(page0, 1, keys, TEST_FILE_ID)).toThrow(
        /Decryption failed/,
      )
      expect(() => decryptPage(page1, 0, keys, TEST_FILE_ID)).toThrow(
        /Decryption failed/,
      )

      expect(decryptPage(page0, 0, keys, TEST_FILE_ID).equals(content)).toBe(
        true,
      )
      expect(decryptPage(page1, 1, keys, TEST_FILE_ID).equals(content)).toBe(
        true,
      )
    })

    it('prevents cross-file page swapping (different file IDs)', () => {
      const keys = deriveKeys('password', randomSalt())
      const content = Buffer.alloc(PAGE_SIZE, 0x42)

      const fileIdA = fileIdFromPath('base/1/16384')
      const fileIdB = fileIdFromPath('base/1/16385')

      const encryptedA = encryptPage(content, 0, keys, fileIdA)

      expect(() => decryptPage(encryptedA, 0, keys, fileIdB)).toThrow(
        /Decryption failed/,
      )
      expect(decryptPage(encryptedA, 0, keys, fileIdA).equals(content)).toBe(
        true,
      )
    })
  })

  describe('wrong key handling', () => {
    it('rejects decryption with wrong key', () => {
      const salt = randomSalt()
      const correctKeys = deriveKeys('correct-password', salt)
      const wrongKeys = deriveKeys('wrong-password', salt)

      const plaintext = Buffer.alloc(PAGE_SIZE, 0xab)
      const encrypted = encryptPage(plaintext, 0, correctKeys, TEST_FILE_ID)

      expect(() => decryptPage(encrypted, 0, wrongKeys, TEST_FILE_ID)).toThrow(
        /Decryption failed/,
      )
    })

    it('error message does not leak key information', () => {
      const salt = randomSalt()
      const correctKeys = deriveKeys('correct-password', salt)
      const wrongKeys = deriveKeys('wrong-password', salt)

      const plaintext = Buffer.alloc(PAGE_SIZE, 0xab)
      const encrypted = encryptPage(plaintext, 0, correctKeys, TEST_FILE_ID)

      try {
        decryptPage(encrypted, 0, wrongKeys, TEST_FILE_ID)
        expect.fail('Should have thrown')
      } catch (error: unknown) {
        const message = (error as Error).message
        expect(message).toContain('Decryption failed')
        expect(message.toLowerCase()).not.toContain('wrong key')
        expect(message.toLowerCase()).not.toContain('password')
      }
    })
  })

  describe('malformed input handling', () => {
    it('rejects truncated encrypted data', () => {
      const keys = deriveKeys('password', randomSalt())
      const plaintext = Buffer.alloc(PAGE_SIZE, 0xab)
      const encrypted = encryptPage(plaintext, 0, keys, TEST_FILE_ID)

      const truncated = encrypted.subarray(0, encrypted.length - 1)
      expect(() => decryptPage(truncated, 0, keys, TEST_FILE_ID)).toThrow(
        /wrong size/,
      )
    })

    it('rejects extended encrypted data', () => {
      const keys = deriveKeys('password', randomSalt())
      const plaintext = Buffer.alloc(PAGE_SIZE, 0xab)
      const encrypted = encryptPage(plaintext, 0, keys, TEST_FILE_ID)

      const extended = Buffer.concat([encrypted, Buffer.from([0x00])])
      expect(() => decryptPage(extended, 0, keys, TEST_FILE_ID)).toThrow(
        /wrong size/,
      )
    })

    it('rejects zero-filled data', () => {
      const keys = deriveKeys('password', randomSalt())
      const zeros = Buffer.alloc(ENCRYPTED_PAGE_SIZE, 0)

      expect(() => decryptPage(zeros, 0, keys, TEST_FILE_ID)).toThrow(
        /Decryption failed/,
      )
    })

    it('rejects random garbage data', () => {
      const keys = deriveKeys('password', randomSalt())
      const garbage = Buffer.alloc(ENCRYPTED_PAGE_SIZE)
      for (let i = 0; i < garbage.length; i++) {
        garbage[i] = Math.floor(Math.random() * 256)
      }

      expect(() => decryptPage(garbage, 0, keys, TEST_FILE_ID)).toThrow(
        /Decryption failed/,
      )
    })
  })
})
