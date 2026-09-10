import { describe, expect, it } from 'vitest'
import { generateAgeIdentity, generateSigningIdentity } from '../src/crypto.js'
import {
    DocumentValidationError,
    canonicalSigningData,
    parseDotenvDocument,
    parseJsonDocument,
    renderEncryptedDocument,
    validateRecipientConsistency,
} from '../src/document.js'

async function fixture() {
    const first = await generateAgeIdentity()
    const second = await generateAgeIdentity()
    const signer = generateSigningIdentity()
    const bobSigner = generateSigningIdentity()
    const members = [
        { id: 'alice', recipient: first.recipient, signingKey: signer.publicKey, isMaintainer: true },
        { id: 'bob', recipient: second.recipient, signingKey: bobSigner.publicKey, isMaintainer: false },
    ]
    const recipients = members.map(({ recipient }) => recipient)
    const marker = (keys = recipients): string => `ENC[age:${Buffer.from(`age-encryption.org/v1\n-> X25519 ${keys[0]}\n-> X25519 ${keys[1]}\n--- tag\nbody`).toString('base64url')}]`
    const dotenv = (value = marker()): string => `# gcrypt: 2\n# gcrypt-recipients: ${recipients.join(',')}\n# gcrypt-maintainers: ${signer.publicKey}\n# gcrypt-member: alice,${first.recipient},${signer.publicKey},true\n# gcrypt-member: bob,${second.recipient},${bobSigner.publicKey},false\n# gcrypt-signature: ${signer.publicKey}:signature\n\nexport TOKEN = "${value}" # keep this\n# keep this comment\nPORT=${value}\n`
    return { dotenv, marker, members, recipients, signer }
}

describe('encrypted dotenv documents', () => {
    it('parses repeated member comments and preserves all non-value formatting when rendering', async () => {
        const { dotenv, marker, members, recipients } = await fixture()
        const document = parseDotenvDocument(dotenv())
        expect(document.metadata.members).toEqual(members)
        expect(document.metadata.recipients).toEqual(recipients)
        expect(document.values.map(({ key }) => key)).toEqual(['TOKEN', 'PORT'])

        const replacement = marker()
        expect(renderEncryptedDocument(document, [replacement, replacement])).toBe(dotenv(replacement))
    })

    it('requires complete, unique member metadata and derived convenience arrays', async () => {
        const { dotenv, members } = await fixture()
        expect(() => parseDotenvDocument(dotenv().replace(/# gcrypt-member:.*\n/gu, ''))).toThrow('members metadata')
        expect(() => parseDotenvDocument(dotenv().replace('alice,', 'alice smith,'))).toThrow('member id')
        expect(() => parseDotenvDocument(dotenv().replace('# gcrypt-member: bob,', '# gcrypt-member: alice,'))).toThrow('member id')
        expect(() => parseDotenvDocument(dotenv().replace(`,${members[1].signingKey},false`, ',false'))).toThrow('member metadata')
        expect(() => parseDotenvDocument(dotenv().replace(',false\n# gcrypt-signature', ',maybe\n# gcrypt-signature'))).toThrow('member metadata')
        expect(() => parseDotenvDocument(dotenv().replace('# gcrypt-maintainers: ' + members[0].signingKey, '# gcrypt-maintainers: ' + members[1].signingKey))).toThrow('does not match members')
        expect(() => parseDotenvDocument(dotenv().replace('# gcrypt-recipients: ', '# gcrypt-recipients: age1wrong,'))).toThrow('does not match members')
        expect(() => parseDotenvDocument(dotenv().replace('PORT=', 'PORT=plain'))).toThrow(DocumentValidationError)
    })
})

describe('encrypted JSON documents', () => {
    it('requires $gcrypt.members and keeps JSON order and whitespace when replacing markers', async () => {
        const { marker, members, recipients, signer } = await fixture()
        const source = `{\n  "$gcrypt": {"version": 2, "members": ${JSON.stringify(members)}, "recipients": ${JSON.stringify(recipients)}, "maintainers": ["${signer.publicKey}"], "signatures": ["${signer.publicKey}:signature"]},\n  "token" : "${marker()}",\n  "port": "${marker()}"\n}`
        const document = parseJsonDocument(source)
        const replacement = marker()
        expect(renderEncryptedDocument(document, [replacement, replacement])).toContain(`"token" : "${replacement}"`)
        expect(document.values.map(({ jsonType }) => jsonType)).toEqual(['string', 'string'])
        expect(() => parseJsonDocument(source.replace(', "members": ' + JSON.stringify(members), ''))).toThrow('members metadata')
        expect(() => parseJsonDocument(source.replace(',"isMaintainer":false', ''))).toThrow('maintainer role')
        expect(() => parseJsonDocument(source.replace('"recipients": ' + JSON.stringify(recipients), '"recipients": []'))).toThrow('recipients metadata')
    })
})

describe('signing and recipient validation', () => {
    it('includes members in canonical signing data and validates age marker recipients', async () => {
        const { dotenv, marker, members } = await fixture()
        const compact = parseDotenvDocument(dotenv())
        const spaced = parseDotenvDocument(dotenv().replace('PORT=', '  PORT = '))
        expect(canonicalSigningData(compact)).toBe(canonicalSigningData(spaced))
        expect(canonicalSigningData(compact)).toContain('"members"')
        expect(canonicalSigningData(compact)).toContain('"isMaintainer":true')
        expect(() => validateRecipientConsistency(compact)).not.toThrow()
        const unexpectedRecipient = (await generateAgeIdentity()).recipient
        expect(() => validateRecipientConsistency(parseDotenvDocument(dotenv(marker([members[0].recipient, unexpectedRecipient]))))).toThrow('do not match')
    })
})
