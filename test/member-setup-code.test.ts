import { describe, expect, it } from 'vitest'
import { generateAgeIdentity, generateSigningIdentity } from '../src/crypto.js'
import { decodeMemberSetupCode, encodeMemberSetupCode } from '../src/member-setup-code.js'

describe('member setup codes', () => {
    it('round-trips the public keys in a versioned one-line code', async () => {
        const age = await generateAgeIdentity()
        const signing = generateSigningIdentity()

        const code = encodeMemberSetupCode({ recipient: age.recipient, signingKey: signing.publicKey })

        expect(code).toMatch(/^gcrypt-member-v1\.[A-Za-z0-9_-]+$/u)
        expect(code).not.toContain(age.identity)
        expect(code).not.toContain(signing.privateKey)
        expect(decodeMemberSetupCode(code)).toEqual({ recipient: age.recipient, signingKey: signing.publicKey })
    })

    it.each([
        '',
        'gcrypt-member-v2.eyJyZWNpcGllbnQiOiJhZ2UxIn0',
        'gcrypt-member-v1.not-base64!',
        'gcrypt-member-v1.eyJyZWNpcGllbnQiOiJhZ2UxIn0',
        'gcrypt-member-v1.eyJyZWNpcGllbnQiOjF9',
    ])('rejects invalid code %j', (code) => {
        expect(() => decodeMemberSetupCode(code)).toThrow('Invalid member setup code')
    })

    it('rejects a non-canonical payload', async () => {
        const age = await generateAgeIdentity()
        const signing = generateSigningIdentity()
        const code = `gcrypt-member-v1.${Buffer.from(JSON.stringify({ signingKey: signing.publicKey, recipient: age.recipient })).toString('base64url')}`

        expect(() => decodeMemberSetupCode(code)).toThrow('Invalid member setup code')
    })
})
