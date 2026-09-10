import { mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { decryptValue, encryptValue, generateAgeIdentity, generateSigningIdentity, signDocument } from '../src/crypto.js'
import {
    createEncryptedDocument,
    decryptEncryptedDocument,
    editEncryptedDocument,
    executeDotenv,
    grantMaintainer,
    grantRecipient,
    maintainerSetup,
    revokeMaintainer,
    revokeRecipient,
    setup,
    managedFileWarning,
    verifyEncryptedDocument,
} from '../src/commands.js'
import { canonicalSigningData, parseEncryptedDocument } from '../src/document.js'
import { defaultAgeIdentityPath, defaultSigningIdentityPath, readDefaultSigningIdentity } from '../src/key-storage.js'
import { encodeMemberSetupCode } from '../src/member-setup-code.js'

const temporaryDirectories: string[] = []
const fileReadOverride = vi.hoisted(() => ({
    handler: undefined as undefined | ((path: string) => Promise<string>),
    actualReadFile: undefined as undefined | ((path: string) => Promise<string>),
}))

vi.mock('node:fs/promises', async (importOriginal) => {
    const actual = await importOriginal<typeof import('node:fs/promises')>()
    fileReadOverride.actualReadFile = (path) => actual.readFile(path, 'utf8')
    return {
        ...actual,
        readFile: (path: string) => fileReadOverride.handler?.(path) ?? actual.readFile(path, 'utf8'),
    }
})

async function temporaryDirectory(): Promise<string> {
    const directory = await mkdtemp(join(tmpdir(), 'gcrypt-commands-'))
    temporaryDirectories.push(directory)
    return directory
}

afterEach(async () => {
    fileReadOverride.handler = undefined
    await Promise.all(temporaryDirectories.splice(0).map((directory) => rm(directory, { force: true, recursive: true })))
})

async function signedDotenv(recipient: string, maintainer: { privateKey: string, publicKey: string }): Promise<string> {
    const marker = await encryptValue('secret', [recipient])
    const unsigned = `# gcrypt: 2\n# gcrypt-recipients: ${recipient}\n# gcrypt-maintainers: ${maintainer.publicKey}\n# gcrypt-member: owner,${recipient},${maintainer.publicKey},true\n# gcrypt-signature: pending\n\nexport TOKEN = "${marker}" # retained\n`
    const document = parseEncryptedDocument(unsigned, 'dotenv')
    const signature = signDocument(canonicalSigningData(document), maintainer.privateKey)
    return unsigned.replace('pending', `${maintainer.publicKey}:${signature}`)
}

async function localMaintainer(homeDirectory: string): Promise<{ privateKey: string, publicKey: string }> {
    const result = await maintainerSetup({ homeDirectory, prompt: { confirm: async () => true } })
    return { privateKey: await readDefaultSigningIdentity(homeDirectory), publicKey: result.publicKey! }
}

function replaceDocumentAfterFirstRead(file: string, replacement: string): () => void {
    let replaced = false
    fileReadOverride.handler = async (path) => {
        const source = await fileReadOverride.actualReadFile!(path)
        if (!replaced && path === file) {
            replaced = true
            await writeFile(file, replacement)
        }
        return source
    }
    return () => { fileReadOverride.handler = undefined }
}

describe('local identity setup', () => {
    it('creates usable age and signing identities for a new developer', async () => {
        const home = await temporaryDirectory()

        const { age, signing } = await setup({ homeDirectory: home })

        expect(age.created).toBe(true)
        expect(age.recipient).toMatch(/^age1/)
        expect(signing.created).toBe(true)
        expect(signing.publicKey).toMatch(/^ed25519:/)
        await expect(readDefaultSigningIdentity(home)).resolves.toMatch(/^ed25519-secret:/)
        expect((await stat(defaultAgeIdentityPath(home))).mode & 0o777).toBe(0o600)
        expect((await stat(defaultSigningIdentityPath(home))).mode & 0o777).toBe(0o600)
        expect((await stat(join(home, '.config', 'gcrypt'))).mode & 0o777).toBe(0o700)
        await expect(setup({ homeDirectory: home })).resolves.toMatchObject({ age: { created: false }, signing: { created: false } })
    })
})

describe('recipient commands', () => {
    it('grants a decrypt-only member with their signing key and signs the updated metadata', async () => {
        const home = await temporaryDirectory()
        const { age: owner } = await setup({ homeDirectory: home, prompt: { confirm: async () => true } })
        const signing = await localMaintainer(home)
        const file = join(home, '.env.enc')
        await writeFile(file, await signedDotenv(owner.recipient, signing))
        const newRecipient = await generateAgeIdentity()
        const newSigning = generateSigningIdentity()

        await grantRecipient(file, { homeDirectory: home, prompt: { memberId: async () => 'collaborator', memberSetupCode: async () => encodeMemberSetupCode({ recipient: newRecipient.recipient, signingKey: newSigning.publicKey }) } })
        const granted = parseEncryptedDocument(await readFile(file, 'utf8'), 'dotenv')
        expect(granted.metadata.recipients).toEqual([owner.recipient, newRecipient.recipient])
        expect(granted.metadata.members).toContainEqual({ id: 'collaborator', recipient: newRecipient.recipient, signingKey: newSigning.publicKey, isMaintainer: false })
        expect(granted.metadata.maintainers).toEqual([signing.publicKey])
        await expect(verifyEncryptedDocument(file)).resolves.toBeUndefined()
        expect(await decryptValue(granted.values[0].marker, newRecipient.identity)).toBe('secret')
        expect(await readFile(file, 'utf8')).toContain('export TOKEN = "ENC[age:')

        await revokeRecipient(file, { homeDirectory: home, prompt: { memberId: async () => 'collaborator' } })
        const revoked = parseEncryptedDocument(await readFile(file, 'utf8'), 'dotenv')
        expect(revoked.metadata.recipients).toEqual([owner.recipient])
        expect(revoked.metadata.members).not.toContainEqual({ id: 'collaborator', recipient: newRecipient.recipient, signingKey: newSigning.publicKey, isMaintainer: false })
        await expect(decryptValue(revoked.values[0].marker, newRecipient.identity)).rejects.toThrow()
    })

    it('rejects an unsigned document before modifying it', async () => {
        const home = await temporaryDirectory()
        const { age: owner } = await setup({ homeDirectory: home, prompt: { confirm: async () => true } })
        const signing = await localMaintainer(home)
        const file = join(home, '.env.enc')
        await writeFile(file, (await signedDotenv(owner.recipient, signing)).replace(/(ed25519:[A-Za-z0-9_-]+):[A-Za-z0-9_-]+/u, '$1:invalid'))

        await expect(grantRecipient(file, { homeDirectory: home, prompt: { memberId: async () => 'duplicate', memberSetupCode: async () => encodeMemberSetupCode({ recipient: owner.recipient, signingKey: generateSigningIdentity().publicKey }) } })).rejects.toThrow('valid maintainer signature')
    })

    it('rejects recipient changes by a decrypt-only user', async () => {
        const home = await temporaryDirectory()
        const { age: owner } = await setup({ homeDirectory: home, prompt: { confirm: async () => true } })
        const signer = await localMaintainer(home)
        const file = join(home, '.env.enc')
        await writeFile(file, await signedDotenv(owner.recipient, signer))
        const decryptOnly = generateSigningIdentity()
        await writeFile(defaultSigningIdentityPath(home), `${decryptOnly.privateKey}\n`, { mode: 0o600 })
        const before = await readFile(file, 'utf8')

        await expect(grantRecipient(file, { homeDirectory: home, prompt: { memberId: async () => 'collaborator', memberSetupCode: async () => encodeMemberSetupCode({ recipient: (await generateAgeIdentity()).recipient, signingKey: generateSigningIdentity().publicKey }) } })).rejects.toThrow('not a listed maintainer')
        await expect(grantMaintainer(file, { homeDirectory: home, prompt: { memberId: async () => 'owner' } })).rejects.toThrow('not a listed maintainer')
        await expect(readFile(file, 'utf8')).resolves.toBe(before)
    })

    it('fully offboards a member by ID, including their maintainer identity', async () => {
        const home = await temporaryDirectory()
        const { age: owner } = await setup({ homeDirectory: home, prompt: { confirm: async () => true } })
        const ownerSigning = await localMaintainer(home)
        const departing = await generateAgeIdentity()
        const departingSigning = generateSigningIdentity()
        const file = join(home, '.env.enc')
        await createEncryptedDocument(file, 'TOKEN=secret\n', {
            homeDirectory: home,
            members: [
                { id: 'owner', recipient: owner.recipient!, signingKey: ownerSigning.publicKey, isMaintainer: true },
                { id: 'departing-member', recipient: departing.recipient, signingKey: departingSigning.publicKey, isMaintainer: true },
            ],
        })

        await revokeRecipient(file, { homeDirectory: home, prompt: { memberId: async () => 'departing-member' } })

        const document = parseEncryptedDocument(await readFile(file, 'utf8'), 'dotenv')
        expect(document.metadata.members).toEqual([{ id: 'owner', recipient: owner.recipient, signingKey: ownerSigning.publicKey, isMaintainer: true }])
        expect(document.metadata.maintainers).toEqual([ownerSigning.publicKey])
        await expect(decryptValue(document.values[0].marker, departing.identity)).rejects.toThrow()
    })
})

describe('maintainer commands', () => {
    it('promotes and demotes an existing member without replacing either key', async () => {
        const home = await temporaryDirectory()
        const { age: recipient } = await setup({ homeDirectory: home, prompt: { confirm: async () => true } })
        const signing = await localMaintainer(home)
        const additionalRecipient = await generateAgeIdentity()
        const marker = await encryptValue('secret', [recipient.recipient, additionalRecipient.recipient])
        const additional = generateSigningIdentity()
        const unsigned = `{"$gcrypt":{"version":2,"members":[{"id":"owner","recipient":"${recipient.recipient}","signingKey":"${signing.publicKey}","isMaintainer":true},{"id":"additional","recipient":"${additionalRecipient.recipient}","signingKey":"${additional.publicKey}","isMaintainer":false}],"recipients":["${recipient.recipient}","${additionalRecipient.recipient}"],"maintainers":["${signing.publicKey}"],"signatures":["pending"]},"token":"${marker}"}`
        const signature = signDocument(canonicalSigningData(parseEncryptedDocument(unsigned, 'json')), signing.privateKey)
        const file = join(home, 'secrets.json')
        await writeFile(file, unsigned.replace('pending', `${signing.publicKey}:${signature}`))

        await grantMaintainer(file, { homeDirectory: home, prompt: { memberId: async () => 'additional' } })
        const promoted = parseEncryptedDocument(await readFile(file, 'utf8'), 'json')
        expect(promoted.metadata.members).toContainEqual({ id: 'additional', recipient: additionalRecipient.recipient, signingKey: additional.publicKey, isMaintainer: true })
        expect(promoted.metadata.maintainers).toEqual([signing.publicKey, additional.publicKey])
        await expect(verifyEncryptedDocument(file)).resolves.toBeUndefined()
        await revokeMaintainer(file, { homeDirectory: home, prompt: { memberId: async () => 'additional' } })
        const revoked = parseEncryptedDocument(await readFile(file, 'utf8'), 'json')
        expect(revoked.metadata.members).toContainEqual({ id: 'additional', recipient: additionalRecipient.recipient, signingKey: additional.publicKey, isMaintainer: false })
        expect(revoked.metadata.maintainers).toEqual([signing.publicKey])
        await expect(decryptValue(revoked.values[0].marker, additionalRecipient.identity)).resolves.toBe('secret')
        await expect(verifyEncryptedDocument(file)).resolves.toBeUndefined()
        await expect(revokeMaintainer(file, { homeDirectory: home, prompt: { memberId: async () => 'owner' } })).rejects.toThrow('final maintainer')
    })
})

describe('encrypted document lifecycle', () => {
    it('creates documents from an explicit member registry and derives convenience arrays', async () => {
        const home = await temporaryDirectory()
        const { age: local } = await setup({ homeDirectory: home, prompt: { confirm: async () => true } })
        const signing = await localMaintainer(home)
        const collaborator = await generateAgeIdentity()
        const file = join(home, '.env.members.enc')

        await createEncryptedDocument(file, 'TOKEN=secret\n', {
            homeDirectory: home,
            members: [
                { id: 'owner', recipient: local.recipient!, signingKey: signing.publicKey, isMaintainer: true },
                { id: 'collaborator', recipient: collaborator.recipient, signingKey: generateSigningIdentity().publicKey, isMaintainer: false },
            ],
        })

        const document = parseEncryptedDocument(await readFile(file, 'utf8'), 'dotenv')
        expect(document.metadata.recipients).toEqual([local.recipient, collaborator.recipient])
        expect(document.metadata.maintainers).toEqual([signing.publicKey])
        await expect(verifyEncryptedDocument(file)).resolves.toBeUndefined()
    })

    it('creates, verifies, decrypts, and injects a signed dotenv document into a child', async () => {
        const home = await temporaryDirectory()
        await setup({ homeDirectory: home, prompt: { confirm: async () => true } })
        await maintainerSetup({ homeDirectory: home, prompt: { confirm: async () => true } })
        const file = join(home, '.env.dev.enc')
        const output = join(home, 'child-output')

        await createEncryptedDocument(file, 'TOKEN=secret\nPORT=3000\n', { homeDirectory: home })
        await expect(readFile(file, 'utf8')).resolves.toContain(`# WARNING: ${managedFileWarning}`)
        await expect(readFile(file, 'utf8')).resolves.toMatch(/# gcrypt-member: local,[^,]+,ed25519:[^,]+,true/u)
        await expect(verifyEncryptedDocument(file)).resolves.toBeUndefined()
        await expect(decryptEncryptedDocument(file, home)).resolves.toBe('TOKEN=secret\nPORT=3000\n')
        await expect(executeDotenv(file, [process.execPath, '-e', `require('node:fs').writeFileSync(${JSON.stringify(output)}, process.env.TOKEN)`], home)).resolves.toBe(0)
        await expect(readFile(output, 'utf8')).resolves.toBe('secret')
    })

    it('adds the managed-file warning to JSON documents', async () => {
        const home = await temporaryDirectory()
        await setup({ homeDirectory: home, prompt: { confirm: async () => true } })
        await maintainerSetup({ homeDirectory: home, prompt: { confirm: async () => true } })
        const file = join(home, 'secrets.json.enc')

        await createEncryptedDocument(file, '{"token":"secret"}', { homeDirectory: home })

        await expect(readFile(file, 'utf8')).resolves.toContain(`"warning": "${managedFileWarning}"`)
        await expect(readFile(file, 'utf8')).resolves.toContain('"members": [')
    })

    it('refuses decryption after a ciphertext change invalidates the signature', async () => {
        const home = await temporaryDirectory()
        await setup({ homeDirectory: home, prompt: { confirm: async () => true } })
        await maintainerSetup({ homeDirectory: home, prompt: { confirm: async () => true } })
        const file = join(home, '.env.dev.enc')
        await createEncryptedDocument(file, 'TOKEN=secret\n', { homeDirectory: home })
        const document = parseEncryptedDocument(await readFile(file, 'utf8'), 'dotenv')
        const replacement = await encryptValue('changed', document.metadata.recipients)
        await writeFile(file, (await readFile(file, 'utf8')).replace(document.values[0].marker, replacement))

        await expect(verifyEncryptedDocument(file)).rejects.toThrow('valid maintainer signature')
        await expect(decryptEncryptedDocument(file, home)).rejects.toThrow()
    })

    it('uses the verified document snapshot when the file changes after it is read', async () => {
        const home = await temporaryDirectory()
        await setup({ homeDirectory: home })
        await maintainerSetup({ homeDirectory: home })
        const file = join(home, '.env.dev.enc')
        await createEncryptedDocument(file, 'TOKEN=secret\n', { homeDirectory: home })
        const original = await readFile(file, 'utf8')
        const document = parseEncryptedDocument(original, 'dotenv')
        const replacement = await encryptValue('changed', document.metadata.recipients)
        const restore = replaceDocumentAfterFirstRead(file, original.replace(document.values[0].marker, replacement))

        try {
            await expect(decryptEncryptedDocument(file, home)).resolves.toBe('TOKEN=secret\n')
        } finally {
            restore()
        }

        await expect(verifyEncryptedDocument(file)).rejects.toThrow('valid maintainer signature')
    })

    it('edits a verified snapshot without rereading the encrypted document', async () => {
        const home = await temporaryDirectory()
        await setup({ homeDirectory: home })
        await maintainerSetup({ homeDirectory: home })
        const file = join(home, '.env.dev.enc')
        await createEncryptedDocument(file, 'TOKEN=secret\n', { homeDirectory: home })
        const original = await readFile(file, 'utf8')
        const document = parseEncryptedDocument(original, 'dotenv')
        const replacement = await encryptValue('changed', document.metadata.recipients)
        const restore = replaceDocumentAfterFirstRead(file, original.replace(document.values[0].marker, replacement))

        try {
            await expect(editEncryptedDocument(file, '/usr/bin/true', home)).resolves.toBeUndefined()
        } finally {
            restore()
        }

        await expect(decryptEncryptedDocument(file, home)).resolves.toBe('TOKEN=secret\n')
    })

    it('refuses a document whose signed member identity was changed', async () => {
        const home = await temporaryDirectory()
        await setup({ homeDirectory: home, prompt: { confirm: async () => true } })
        await maintainerSetup({ homeDirectory: home, prompt: { confirm: async () => true } })
        const file = join(home, '.env.dev.enc')
        await createEncryptedDocument(file, 'TOKEN=secret\n', { homeDirectory: home })

        await writeFile(file, (await readFile(file, 'utf8')).replace('# gcrypt-member: local,', '# gcrypt-member: impersonated,'))

        await expect(verifyEncryptedDocument(file)).rejects.toThrow('valid maintainer signature')
    })

    it('refuses a document whose signed member role was changed', async () => {
        const home = await temporaryDirectory()
        const { age: owner } = await setup({ homeDirectory: home })
        const signing = await localMaintainer(home)
        const collaborator = await generateAgeIdentity()
        const collaboratorSigning = generateSigningIdentity()
        const file = join(home, '.env.dev.enc')
        await createEncryptedDocument(file, 'TOKEN=secret\n', {
            homeDirectory: home,
            members: [
                { id: 'owner', recipient: owner.recipient, signingKey: signing.publicKey, isMaintainer: true },
                { id: 'collaborator', recipient: collaborator.recipient, signingKey: collaboratorSigning.publicKey, isMaintainer: false },
            ],
        })

        await writeFile(file, (await readFile(file, 'utf8'))
            .replace(`# gcrypt-maintainers: ${signing.publicKey}`, `# gcrypt-maintainers: ${signing.publicKey},${collaboratorSigning.publicKey}`)
            .replace(`,${collaboratorSigning.publicKey},false`, `,${collaboratorSigning.publicKey},true`))

        await expect(verifyEncryptedDocument(file)).rejects.toThrow('valid maintainer signature')
    })

})
