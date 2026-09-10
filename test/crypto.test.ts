import { chmod, mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import {
    decryptValue,
    encryptValue,
    generateAgeIdentity,
    generateSigningIdentity,
    signDocument,
    verifyDocument,
} from '../src/crypto.js'
import {
    readDefaultAgeIdentity,
    readDefaultSigningIdentity,
    writeDefaultAgeIdentity,
    writeDefaultSigningIdentity,
} from '../src/key-storage.js'

const temporaryDirectories: string[] = []

async function temporaryHome(): Promise<string> {
    const directory = await mkdtemp(join(tmpdir(), 'gcrypt-'))
    temporaryDirectories.push(directory)
    return directory
}

afterEach(async () => {
    await Promise.all(temporaryDirectories.splice(0).map((directory) => rm(directory, { force: true, recursive: true })))
})

describe('age value encryption', () => {
    it('encrypts an inline value that its X25519 identity decrypts', async () => {
        const identity = await generateAgeIdentity()
        const encrypted = await encryptValue('secret value', [identity.recipient])

        expect(encrypted).toMatch(/^ENC\[age:[A-Za-z0-9_-]+\]$/)
        await expect(decryptValue(encrypted, identity.identity)).resolves.toBe('secret value')
    })

    it('rejects malformed recipients, markers, and identities that cannot decrypt', async () => {
        const first = await generateAgeIdentity()
        const second = await generateAgeIdentity()

        await expect(encryptValue('secret', ['not-a-recipient'])).rejects.toThrow('Invalid access key')
        await expect(decryptValue('ENC[age:not base64]', first.identity)).rejects.toThrow('Invalid encrypted value')
        await expect(decryptValue(await encryptValue('secret', [first.recipient]), second.identity)).rejects.toThrow()
    })
})

describe('maintainer signatures', () => {
    it('signs and verifies a document with its matching public key', () => {
        const signingIdentity = generateSigningIdentity()
        const signature = signDocument('{"version":2}', signingIdentity.privateKey)

        expect(verifyDocument('{"version":2}', signature, signingIdentity.publicKey)).toBe(true)
        expect(verifyDocument('{"version":3}', signature, signingIdentity.publicKey)).toBe(false)
    })

    it('rejects malformed keys and signatures', () => {
        const signingIdentity = generateSigningIdentity()
        const signature = signDocument('document', signingIdentity.privateKey)

        expect(() => signDocument('document', 'ed25519-secret:not-a-key')).toThrow('Invalid Ed25519 private key')
        expect(() => verifyDocument('document', 'not-base64', signingIdentity.publicKey)).toThrow('Invalid Ed25519 signature')
        expect(() => verifyDocument('document', signature, 'ed25519:not-a-key')).toThrow('Invalid Ed25519 public key')
    })
})

describe('local key storage', () => {
    it('stores age and signing identities in private default files', async () => {
        const home = await temporaryHome()
        const ageIdentity = await generateAgeIdentity()
        const signingIdentity = generateSigningIdentity()

        await writeDefaultAgeIdentity(ageIdentity.identity, home)
        await writeDefaultSigningIdentity(signingIdentity.privateKey, home)

        await expect(readDefaultAgeIdentity(home)).resolves.toBe(ageIdentity.identity)
        await expect(readDefaultSigningIdentity(home)).resolves.toBe(signingIdentity.privateKey)
    })

    it('refuses a group-readable private key file', async () => {
        const home = await temporaryHome()
        const identity = await generateAgeIdentity()

        const filePath = await writeDefaultAgeIdentity(identity.identity, home)
        await chmod(filePath, 0o640)

        await expect(readDefaultAgeIdentity(home)).rejects.toThrow('group- or world-readable')
    })
})
