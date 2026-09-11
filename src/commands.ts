import { mkdtemp, readFile, rename, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { basename, dirname, join } from 'node:path'
import { spawn } from 'node:child_process'
import { parse as parseDotenv } from 'dotenv'
import {
    ageRecipientForIdentity,
    decryptValue,
    encryptValue,
    generateAgeIdentity,
    generateSigningIdentity,
    signDocument,
    signingPublicKeyForIdentity,
    validateSigningPublicKey,
    verifyDocument,
} from './crypto.js'
import {
    canonicalSigningData,
    type DocumentFormat,
    type DocumentMember,
    type DocumentMetadata,
    DocumentValidationError,
    type ParsedDocument,
    parseEncryptedDocument,
    renderEncryptedDocument,
} from './document.js'
import {
    defaultAgeIdentityPath,
    defaultSigningIdentityPath,
    readDefaultAgeIdentity,
    readDefaultSigningIdentity,
    writeDefaultAgeIdentity,
    writeDefaultSigningIdentity,
} from './key-storage.js'
import { decodeMemberSetupCode, encodeMemberSetupCode } from './member-setup-code.js'

export const managedFileWarning = 'Do not manually edit this file. Use gcrypt instead.'

export interface ChangePrompt {
    memberId?: () => Promise<string>
    memberSetupCode?: () => Promise<string>
}

export interface CommandOptions {
    homeDirectory?: string
    prompt: ChangePrompt
}

export interface SetupOptions {
    homeDirectory?: string
    /** @deprecated Identities are now created automatically. */
    prompt?: { confirm(): Promise<boolean> }
}

export interface SetupResult {
    age: AgeSetupResult
    signing: SigningSetupResult
    memberSetupCode: string
}

export interface AgeSetupResult {
    created: boolean
    path: string
    recipient: string
}

export interface SigningSetupResult {
    created: boolean
    path: string
    publicKey: string
}

export interface InitialDocumentOptions {
    homeDirectory?: string
    members?: DocumentMember[]
    memberId?: string
}

async function ageSetup({ homeDirectory }: SetupOptions = {}): Promise<AgeSetupResult> {
    try {
        const identity = await readDefaultAgeIdentity(homeDirectory)
        return { created: false, path: defaultAgeIdentityPath(homeDirectory), recipient: await ageRecipientForIdentity(identity) }
    } catch (error) {
        if (!isMissingFile(error)) throw error
    }
    const identity = await generateAgeIdentity()
    return { created: true, path: await writeDefaultAgeIdentity(identity.identity, homeDirectory), recipient: identity.recipient }
}

export async function maintainerSetup({ homeDirectory }: SetupOptions = {}): Promise<SigningSetupResult> {
    try {
        const privateKey = await readDefaultSigningIdentity(homeDirectory)
        return { created: false, path: defaultSigningIdentityPath(homeDirectory), publicKey: signingPublicKeyForIdentity(privateKey) }
    } catch (error) {
        if (!isMissingFile(error)) throw error
    }
    const identity = generateSigningIdentity()
    return { created: true, path: await writeDefaultSigningIdentity(identity.privateKey, homeDirectory), publicKey: identity.publicKey }
}

export async function setup(options: SetupOptions = {}): Promise<SetupResult> {
    const [age, signing] = await Promise.all([ageSetup(options), maintainerSetup(options)])
    return { age, signing, memberSetupCode: encodeMemberSetupCode({ recipient: age.recipient, signingKey: signing.publicKey }) }
}

export async function grantRecipient(filePath: string, options: CommandOptions): Promise<void> {
    const memberId = await requested(options.prompt.memberId, 'member ID')
    validateMemberId(memberId)
    const { recipient, signingKey } = decodeMemberSetupCode(await requested(options.prompt.memberSetupCode, 'member setup code'))
    await changeMembers(filePath, options, (members) => {
        if (members.some((member) => member.id === memberId)) throw new Error('Member ID is already listed')
        if (members.some((member) => member.recipient === recipient)) throw new Error('This access key is already assigned to a member')
        if (members.some((member) => member.signingKey === signingKey)) throw new Error('Signing key is already listed')
        return [...members, { id: memberId, recipient, signingKey, isMaintainer: false }]
    })
}

export async function revokeRecipient(filePath: string, options: CommandOptions): Promise<void> {
    const memberId = await requested(options.prompt.memberId, 'member ID')
    await changeMembers(filePath, options, (members) => {
        const member = members.find((candidate) => candidate.id === memberId)
        if (!member) throw new Error('Member ID is not listed')
        if (members.length === 1) throw new Error('Cannot remove the final recipient')
        if (member.isMaintainer && members.filter((candidate) => candidate.isMaintainer).length === 1) throw new Error('Cannot remove the final maintainer')
        return members.filter((candidate) => candidate.id !== memberId)
    })
}

export async function grantMaintainer(filePath: string, options: CommandOptions): Promise<void> {
    const memberId = await requested(options.prompt.memberId, 'member ID')
    await changeMembers(filePath, options, (members) => {
        const member = members.find((candidate) => candidate.id === memberId)
        if (!member) throw new Error('Member ID is not listed')
        if (member.isMaintainer) throw new Error('Member is already a maintainer')
        return members.map((candidate) => candidate.id === memberId ? { ...candidate, isMaintainer: true } : candidate)
    })
}

export async function revokeMaintainer(filePath: string, options: CommandOptions): Promise<void> {
    const memberId = await requested(options.prompt.memberId, 'member ID')
    await changeMembers(filePath, options, (members) => {
        const member = members.find((candidate) => candidate.id === memberId)
        if (!member) throw new Error('Member ID is not listed')
        if (!member.isMaintainer) throw new Error('Member is not a maintainer')
        if (members.filter((member) => member.isMaintainer).length === 1) throw new Error('Cannot remove the final maintainer')
        return members.map((candidate) => candidate.id === memberId ? { ...candidate, isMaintainer: false } : candidate)
    })
}

/** Create a new signed encrypted dotenv or JSON document from plaintext input. */
export async function createEncryptedDocument(filePath: string, plaintext: string, options: InitialDocumentOptions = {}): Promise<void> {
    const identity = await readDefaultAgeIdentity(options.homeDirectory)
    const privateKey = await readDefaultSigningIdentity(options.homeDirectory)
    const publicKey = signingPublicKeyForIdentity(privateKey)
    const members = options.members ?? [{ id: options.memberId ?? 'local', recipient: await ageRecipientForIdentity(identity), signingKey: publicKey, isMaintainer: true }]
    const metadata = metadataForMembers(members)
    const format = filePath.endsWith('.json.enc') || filePath.endsWith('.json') ? 'json' : 'dotenv'
    const source = format === 'json'
        ? await encryptJson(plaintext, metadata)
        : await encryptDotenv(plaintext, metadata)
    const document = parseEncryptedDocument(source, format)
    const signature = signDocument(canonicalSigningData(document), privateKey)
    await atomicWrite(filePath, renderMetadata(source, format, { ...document.metadata, signatures: [`${publicKey}:${signature}`] }))
}

export async function verifyEncryptedDocument(filePath: string): Promise<void> {
    await loadVerifiedDocument(filePath)
}

export async function decryptEncryptedDocument(filePath: string, homeDirectory?: string): Promise<string> {
    const { document } = await loadVerifiedDocument(filePath)
    const identity = await readDefaultAgeIdentity(homeDirectory)
    return decryptParsedDocument(document, identity)
}

async function decryptParsedDocument(document: ParsedDocument, identity: string): Promise<string> {
    const values = await Promise.all(document.values.map(({ marker }) => decryptValue(marker, identity)))
    if (document.format === 'dotenv') return document.values.map(({ key }, index) => `${key}=${values[index]}`).join('\n') + (values.length ? '\n' : '')
    const decrypted = JSON.parse(document.source) as Record<string, unknown>
    delete decrypted.$gcrypt
    for (const [index, value] of document.values.entries()) setJsonPath(decrypted, value.key, parseJsonScalar(values[index]))
    return `${JSON.stringify(decrypted, undefined, 2)}\n`
}

export async function editEncryptedDocument(filePath: string, editor: string, homeDirectory?: string): Promise<void> {
    // Editing must be authorized before a plaintext temporary file is created.
    const authorized = await loadAuthorizedDocument(filePath, homeDirectory)
    const plaintext = await decryptParsedDocument(authorized.document, authorized.identity)
    const directory = await mkdtemp(join(tmpdir(), 'gcrypt-edit-'))
    const temporaryFile = join(directory, basename(filePath).replace(/\.enc$/u, ''))
    try {
        await writeFile(temporaryFile, plaintext, { encoding: 'utf8', mode: 0o600 })
        const [command, ...arguments_] = editor.trim().split(/\s+/u)
        if (!command) throw new Error('An editor is required')
        const result = await new Promise<number | null>((resolve, reject) => {
            const child = spawn(command, [...arguments_, temporaryFile], { stdio: 'inherit' })
            child.once('error', reject)
            child.once('exit', resolve)
        })
        if (result !== 0) throw new Error(`Editor exited with status ${result ?? 'unknown'}`)
        const updated = await readFile(temporaryFile, 'utf8')
        await createEncryptedDocument(filePath, updated, {
            homeDirectory,
            members: authorized.document.metadata.members,
        })
    } finally {
        await rm(directory, { force: true, recursive: true })
    }
}

export async function executeDotenv(filePath: string, command: string[], homeDirectory?: string): Promise<number> {
    if (command.length === 0) throw new Error('A command after -- is required')
    const { document } = await loadVerifiedDocument(filePath)
    if (document.format !== 'dotenv') throw new Error('exec supports dotenv files only')
    const identity = await readDefaultAgeIdentity(homeDirectory)
    const environment = parseDotenv(await decryptParsedDocument(document, identity))
    return new Promise((resolve, reject) => {
        const child = spawn(command[0], command.slice(1), { stdio: 'inherit', env: { ...process.env, ...environment } })
        child.once('error', reject)
        child.once('exit', (code) => resolve(code ?? 1))
    })
}

async function changeMembers(filePath: string, options: CommandOptions, update: (members: DocumentMember[]) => DocumentMember[]): Promise<void> {
    const { source, document, format, identity, privateKey, publicKey } = await loadAuthorizedDocument(filePath, options.homeDirectory)
    const metadata = metadataForMembers(update(document.metadata.members), document.metadata.version)
    const plaintextValues = await Promise.all(document.values.map(({ marker }) => decryptValue(marker, identity)))
    const markers = await Promise.all(plaintextValues.map((value) => encryptValue(value, metadata.recipients)))
    await writeSignedDocument(filePath, source, document, format, { ...metadata, signatures: document.metadata.signatures }, markers, privateKey, publicKey)
}

async function loadAuthorizedDocument(filePath: string, homeDirectory?: string): Promise<{ source: string, document: ParsedDocument, format: DocumentFormat, identity: string, privateKey: string, publicKey: string }> {
    const { source, format, document } = await loadVerifiedDocument(filePath)
    const identity = await readDefaultAgeIdentity(homeDirectory)
    const privateKey = await readDefaultSigningIdentity(homeDirectory)
    const publicKey = signingPublicKeyForIdentity(privateKey)
    if (!document.metadata.maintainers.includes(publicKey)) throw new Error('Local signing identity is not a listed maintainer')
    return { source, document, format, identity, privateKey, publicKey }
}

async function writeSignedDocument(filePath: string, source: string, document: ParsedDocument, format: DocumentFormat, metadata: DocumentMetadata, markers: string[], privateKey: string, publicKey: string): Promise<void> {
    const updated = { ...document, metadata, values: document.values.map((value, index) => ({ ...value, marker: markers[index] })) }
    const signature = signDocument(canonicalSigningData(updated), privateKey)
    const signedMetadata = { ...metadata, signatures: [`${publicKey}:${signature}`] }
    const renderedValues = renderEncryptedDocument(document, markers)
    await atomicWrite(filePath, renderMetadata(renderedValues, format, signedMetadata))
}

async function loadDocument(filePath: string): Promise<{ source: string, document: ParsedDocument, format: DocumentFormat }> {
    const source = await readFile(filePath, 'utf8')
    const format = source.trimStart().startsWith('{') ? 'json' : 'dotenv'
    return { source, format, document: parseEncryptedDocument(source, format) }
}

async function loadVerifiedDocument(filePath: string): Promise<{ source: string, document: ParsedDocument, format: DocumentFormat }> {
    let loaded: { source: string, document: ParsedDocument, format: DocumentFormat }
    try {
        loaded = await loadDocument(filePath)
    } catch (error) {
        if (error instanceof DocumentValidationError) throw tamperedDocumentError()
        throw error
    }
    try {
        validateMaintainers(loaded.document)
        if (!hasValidSignature(loaded.document)) throw tamperedDocumentError()
        return loaded
    } catch {
        throw tamperedDocumentError()
    }
}

function tamperedDocumentError(): Error {
    return new Error('This file has been tampered with and is no longer valid')
}

async function encryptDotenv(plaintext: string, metadata: DocumentMetadata): Promise<string> {
    const values = parseDotenv(plaintext)
    const lines = await Promise.all(Object.entries(values).map(async ([key, value]) => `${key}=${await encryptValue(value, metadata.recipients)}`))
    return `# WARNING: ${managedFileWarning}\n# gcrypt: 2\n# gcrypt-recipients: ${metadata.recipients.join(',')}\n# gcrypt-maintainers: ${metadata.maintainers.join(',')}\n${metadata.members.map(renderDotenvMember).join('\n')}\n# gcrypt-signature: pending\n\n${lines.join('\n')}\n`
}

async function encryptJson(plaintext: string, metadata: DocumentMetadata): Promise<string> {
    let values: unknown
    try { values = JSON.parse(plaintext) } catch { throw new Error('Invalid JSON document') }
    if (typeof values !== 'object' || values === null || Array.isArray(values) || Object.hasOwn(values, '$gcrypt')) throw new Error('JSON document must be a top-level object without $gcrypt')
    const jsonMetadata = { ...metadata, version: 3 as const }
    const encrypted: Record<string, unknown> = { $gcrypt: { warning: managedFileWarning, ...jsonMetadata, signatures: ['pending'] } }
    for (const [key, value] of Object.entries(values)) encrypted[key] = await encryptJsonValue(value, jsonMetadata)
    return `${JSON.stringify(encrypted, undefined, 2)}\n`
}

async function encryptJsonValue(value: unknown, metadata: DocumentMetadata): Promise<unknown> {
    if (Array.isArray(value)) return Promise.all(value.map((entry) => encryptJsonValue(entry, metadata)))
    if (value !== null && typeof value === 'object') return Object.fromEntries(await Promise.all(Object.entries(value).map(async ([key, entry]) => [key, await encryptJsonValue(entry, metadata)])))
    return encryptValue(JSON.stringify(value), metadata.recipients)
}

function parseJsonScalar(value: string): string | number | boolean | null {
    try {
        const parsed: unknown = JSON.parse(value)
        if (parsed === null || ['string', 'number', 'boolean'].includes(typeof parsed)) return parsed as string | number | boolean | null
    } catch { /* Older documents encrypted string values directly. */ }
    return value
}

function setJsonPath(root: Record<string, unknown>, path: string, value: string | number | boolean | null): void {
    const segments = path.slice(1).split('/').map((segment) => segment.replace(/~1/gu, '/').replace(/~0/gu, '~'))
    const key = segments.pop()
    if (key === undefined) throw new Error('Invalid JSON value path')
    let parent: Record<string, unknown> | unknown[] = root
    for (const segment of segments) {
        const next = Array.isArray(parent) ? parent[Number(segment)] : parent[segment]
        if (next === null || typeof next !== 'object') throw new Error('Invalid JSON value path')
        parent = next as Record<string, unknown> | unknown[]
    }
    if (Array.isArray(parent)) parent[Number(key)] = value
    else parent[key] = value
}

async function atomicWrite(filePath: string, value: string): Promise<void> {
    const temporary = join(dirname(filePath), `.${basename(filePath)}.${process.pid}.tmp`)
    await writeFile(temporary, value, { encoding: 'utf8', mode: 0o600 })
    await rename(temporary, filePath)
}

function hasValidSignature(document: ParsedDocument): boolean {
    const data = canonicalSigningData(document)
    const seenSigners = new Set<string>()
    for (const maintainer of document.metadata.maintainers) validateSigningPublicKey(maintainer)
    for (const signature of document.metadata.signatures) {
        const match = /^(ed25519:[A-Za-z0-9_-]+):([A-Za-z0-9_-]+)$/u.exec(signature)
        if (!match || !document.metadata.maintainers.includes(match[1]) || seenSigners.has(match[1])) {
            throw new Error('Document has malformed or duplicate maintainer signatures')
        }
        seenSigners.add(match[1])
        try {
            if (verifyDocument(data, match[2], match[1])) return true
        } catch {
            throw new Error('Document does not have a valid maintainer signature')
        }
    }
    return false
}

function validateMaintainers(document: ParsedDocument): void {
    for (const maintainer of document.metadata.maintainers) validateSigningPublicKey(maintainer)
}

function renderMetadata(source: string, format: DocumentFormat, metadata: DocumentMetadata): string {
    if (format === 'json') {
        const parsed = JSON.parse(source) as Record<string, unknown>
        parsed.$gcrypt = { warning: managedFileWarning, ...metadata }
        return `${JSON.stringify(parsed, undefined, 2)}\n`
    }
    const lines = source.split(/(\r\n|\n|\r)/u)
    const replacement = new Map<string, string>([
        ['version', '# gcrypt: 2'],
        ['recipients', `# gcrypt-recipients: ${metadata.recipients.join(',')}`],
        ['maintainers', `# gcrypt-maintainers: ${metadata.maintainers.join(',')}`],
    ])
    let wroteSignature = false
    let memberIndex = 0
    for (let index = 0; index < lines.length; index += 2) {
        const match = /^\s*#\s*gcrypt(?:-(member|recipients|maintainers|signature))?\s*:/u.exec(lines[index])
        if (!match) continue
        const name = match[1] ?? 'version'
        if (name === 'member') {
            const member = metadata.members[memberIndex]
            lines[index] = member ? renderDotenvMember(member) : ''
            memberIndex += 1
        } else if (name === 'signature') {
            if (wroteSignature) lines[index] = ''
            else {
                lines[index] = `# gcrypt-signature: ${metadata.signatures[0]}`
                wroteSignature = true
            }
        } else lines[index] = replacement.get(name)!
    }
    if (!wroteSignature) {
        const maintainerIndex = lines.findIndex((line) => line.startsWith('# gcrypt-maintainers:'))
        lines.splice(maintainerIndex + 2, 0, `# gcrypt-signature: ${metadata.signatures[0]}`, '\n')
    }
    const missingMembers = metadata.members.slice(memberIndex).map(renderDotenvMember)
    if (missingMembers.length > 0) {
        const signatureIndex = lines.findIndex((line) => line.startsWith('# gcrypt-signature:'))
        lines.splice(signatureIndex === -1 ? lines.length : signatureIndex, 0, ...missingMembers.flatMap((line) => [line, '\n']))
    }
    const rendered = lines.join('')
    return rendered.startsWith(`# WARNING: ${managedFileWarning}`) ? rendered : `# WARNING: ${managedFileWarning}\n${rendered}`
}

function metadataForMembers(members: DocumentMember[], version: DocumentMetadata['version'] = 2): DocumentMetadata {
    return {
        version,
        members,
        recipients: members.map(({ recipient }) => recipient),
        maintainers: members.flatMap(({ signingKey, isMaintainer }) => isMaintainer ? [signingKey] : []),
        signatures: [],
    }
}

function renderDotenvMember({ id, recipient, signingKey, isMaintainer }: DocumentMember): string {
    return `# gcrypt-member: ${id},${recipient},${signingKey},${isMaintainer}`
}

function validateMemberId(memberId: string): void {
    if (/\s|,/u.test(memberId)) throw new Error('Member ID must not contain spaces or commas')
}

async function requested(request: (() => Promise<string>) | undefined, name: string): Promise<string> {
    if (!request) throw new Error(`A ${name} prompt is required`)
    const value = (await request()).trim()
    if (!value) throw new Error(`A ${name} is required`)
    return value
}

function isMissingFile(error: unknown): error is NodeJS.ErrnoException {
    return typeof error === 'object' && error !== null && 'code' in error && error.code === 'ENOENT'
}
