import { createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify } from 'node:crypto'
import { Decrypter, Encrypter, generateX25519Identity, identityToRecipient } from 'age-encryption'

const encryptedValuePattern = /^ENC\[age:([A-Za-z0-9_-]+)\]$/
const publicKeyPrefix = 'ed25519:'
const privateKeyPrefix = 'ed25519-secret:'

export interface AgeIdentity {
    identity: string
    recipient: string
}

export interface SigningIdentity {
    privateKey: string
    publicKey: string
}

export async function generateAgeIdentity(): Promise<AgeIdentity> {
    const identity = await generateX25519Identity()
    return { identity, recipient: await identityToRecipient(identity) }
}

export async function ageRecipientForIdentity(identity: string): Promise<string> {
    validateIdentity(identity)
    return identityToRecipient(identity)
}

export async function encryptValue(value: string, recipients: string[]): Promise<string> {
    if (recipients.length === 0) {
        throw new Error('At least one access key is required')
    }

    const encrypter = new Encrypter()
    for (const recipient of recipients) {
        validateRecipient(recipient)
        encrypter.addRecipient(recipient)
    }

    const ciphertext = await encrypter.encrypt(value)
    return `ENC[age:${Buffer.from(ciphertext).toString('base64url')}]`
}

export async function decryptValue(encryptedValue: string, identity: string): Promise<string> {
    const match = encryptedValuePattern.exec(encryptedValue)
    if (!match) {
        throw new Error('Invalid encrypted value')
    }

    validateIdentity(identity)
    const decrypter = new Decrypter()
    decrypter.addIdentity(identity)
    return decrypter.decrypt(Buffer.from(match[1], 'base64url'), 'text')
}

export function generateSigningIdentity(): SigningIdentity {
    const { privateKey, publicKey } = generateKeyPairSync('ed25519')
    return {
        privateKey: `${privateKeyPrefix}${privateKey.export({ format: 'der', type: 'pkcs8' }).toString('base64url')}`,
        publicKey: `${publicKeyPrefix}${publicKey.export({ format: 'der', type: 'spki' }).toString('base64url')}`,
    }
}

export function signDocument(document: string, privateKey: string): string {
    return sign(null, Buffer.from(document), parsePrivateKey(privateKey)).toString('base64url')
}

export function verifyDocument(document: string, signature: string, publicKey: string): boolean {
    if (!/^[A-Za-z0-9_-]+$/.test(signature)) {
        throw new Error('Invalid Ed25519 signature')
    }

    let signatureBytes: Buffer
    try {
        signatureBytes = Buffer.from(signature, 'base64url')
    } catch {
        throw new Error('Invalid Ed25519 signature')
    }
    if (signatureBytes.length !== 64) {
        throw new Error('Invalid Ed25519 signature')
    }

    return verify(null, Buffer.from(document), parsePublicKey(publicKey), signatureBytes)
}

export function signingPublicKeyForIdentity(privateKey: string): string {
    const publicKey = createPublicKey(parsePrivateKey(privateKey))
    return `${publicKeyPrefix}${publicKey.export({ format: 'der', type: 'spki' }).toString('base64url')}`
}

export function validateAgeRecipient(recipient: string): void {
    validateRecipient(recipient)
}

export function validateSigningPublicKey(publicKey: string): void {
    parsePublicKey(publicKey)
}

function validateRecipient(recipient: string): void {
    if (!recipient.startsWith('age1') || recipient.startsWith('age1pq') || recipient.startsWith('age1tag')) {
        throw new Error('Invalid access key')
    }

    try {
        const encrypter = new Encrypter()
        encrypter.addRecipient(recipient)
    } catch {
        throw new Error('Invalid access key')
    }
}

function validateIdentity(identity: string): void {
    if (!identity.startsWith('AGE-SECRET-KEY-1')) {
        throw new Error('Invalid age identity')
    }

    try {
        const decrypter = new Decrypter()
        decrypter.addIdentity(identity)
    } catch {
        throw new Error('Invalid age identity')
    }
}

function parsePrivateKey(privateKey: string) {
    if (!privateKey.startsWith(privateKeyPrefix)) {
        throw new Error('Invalid Ed25519 private key')
    }

    try {
        const key = createPrivateKey({
            key: Buffer.from(privateKey.slice(privateKeyPrefix.length), 'base64url'),
            format: 'der',
            type: 'pkcs8',
        })
        if (key.asymmetricKeyType !== 'ed25519') {
            throw new Error('not an Ed25519 key')
        }
        return key
    } catch {
        throw new Error('Invalid Ed25519 private key')
    }
}

function parsePublicKey(publicKey: string) {
    if (!publicKey.startsWith(publicKeyPrefix)) {
        throw new Error('Invalid Ed25519 public key')
    }

    try {
        const key = createPublicKey({
            key: Buffer.from(publicKey.slice(publicKeyPrefix.length), 'base64url'),
            format: 'der',
            type: 'spki',
        })
        if (key.asymmetricKeyType !== 'ed25519') {
            throw new Error('not an Ed25519 key')
        }
        return key
    } catch {
        throw new Error('Invalid Ed25519 public key')
    }
}
