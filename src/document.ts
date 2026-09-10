export type DocumentFormat = 'dotenv' | 'json'
export type JsonScalarType = 'string' | 'number' | 'boolean' | 'null'

export interface DocumentMetadata {
    version: 2
    members: DocumentMember[]
    recipients: string[]
    maintainers: string[]
    signatures: string[]
}

export interface DocumentMember {
    id: string
    recipient: string
    signingKey: string
    isMaintainer: boolean
}

export interface EncryptedValue {
    key: string
    marker: string
    jsonType?: JsonScalarType
}

export interface EncryptedDocument {
    format: DocumentFormat
    metadata: DocumentMetadata
    values: EncryptedValue[]
}

interface SourceValue extends EncryptedValue {
    start: number
    end: number
}

export interface ParsedDocument extends EncryptedDocument {
    source: string
    sourceValues: SourceValue[]
}

export class DocumentValidationError extends Error {
    constructor(message: string) {
        super(message)
        this.name = 'DocumentValidationError'
    }
}

const markerPattern = /^ENC\[age:([A-Za-z0-9_-]+)\]$/
const metadataKeys = new Set(['warning', 'version', 'members', 'recipients', 'maintainers', 'signatures'])

export function parseEncryptedDocument(source: string, format: DocumentFormat): ParsedDocument {
    return format === 'dotenv' ? parseDotenvDocument(source) : parseJsonDocument(source)
}

export function parseDotenvDocument(source: string): ParsedDocument {
    const metadata: Partial<DocumentMetadata> = { signatures: [] }
    const values: SourceValue[] = []
    const lines = source.matchAll(/.*(?:\r\n|\n|\r|$)/g)

    for (const match of lines) {
        const line = match[0]
        if (line === '') continue
        const content = line.replace(/\r\n$|[\r\n]$/u, '')
        const metadataMatch = /^\s*#\s*gcrypt(?:-(member|recipients|maintainers|signature))?\s*:\s*(.*?)\s*$/u.exec(content)
        if (metadataMatch) {
            const [, name, value] = metadataMatch
            if (name === undefined) {
                if (metadata.version !== undefined) throw new DocumentValidationError('Duplicate gcrypt version metadata')
                if (value !== '2') throw new DocumentValidationError('Unsupported gcrypt version')
                metadata.version = 2
            } else if (name === 'signature') {
                metadata.signatures!.push(value)
            } else if (name === 'member') {
                metadata.members ??= []
                metadata.members.push(parseDotenvMember(value))
            } else {
                const key = name === 'recipients' ? 'recipients' : 'maintainers'
                if (metadata[key] !== undefined) throw new DocumentValidationError(`Duplicate gcrypt ${key} metadata`)
                metadata[key] = splitMetadataList(value, key)
            }
            continue
        }

        const assignment = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*/u.exec(content)
        if (!assignment) continue
        const valueStart = match.index + assignment[0].length
        const rawValue = content.slice(assignment[0].length)
        const marker = parseDotenvMarker(rawValue)
        if (marker) {
            values.push({ key: assignment[1], marker: marker.value, start: valueStart + marker.start, end: valueStart + marker.end })
        } else {
            throw new DocumentValidationError(`Dotenv value ${assignment[1]} is not an encrypted marker`)
        }
    }

    const parsed = createParsedDocument('dotenv', source, metadata, values)
    ensureUniqueKeys(parsed.values)
    return parsed
}

export function parseJsonDocument(source: string): ParsedDocument {
    let document: unknown
    try {
        document = JSON.parse(source)
    } catch {
        throw new DocumentValidationError('Invalid JSON document')
    }
    if (!isRecord(document) || Array.isArray(document)) throw new DocumentValidationError('JSON document must be a top-level object')
    if (!Object.hasOwn(document, '$gcrypt')) throw new DocumentValidationError('JSON document is missing $gcrypt metadata')

    const metadata = parseJsonMetadata(document.$gcrypt)
    const values: SourceValue[] = []
    const scanner = new JsonObjectScanner(source)
    for (const property of scanner.properties()) {
        if (property.key === '$gcrypt') continue
        if (property.type === 'object' || property.type === 'array') {
            throw new DocumentValidationError(`JSON value ${property.key} must be a scalar`)
        }
        if (property.type !== 'string' || !isEncryptedMarker(property.value)) {
            throw new DocumentValidationError(`JSON value ${property.key} is not an encrypted marker`)
        }
        values.push({ key: property.key, marker: property.value, jsonType: property.type, start: property.start, end: property.end })
    }
    return { format: 'json', source, metadata, values, sourceValues: values }
}

export function renderEncryptedDocument(document: ParsedDocument, markers: readonly string[]): string {
    if (markers.length !== document.sourceValues.length) throw new DocumentValidationError('Replacement marker count does not match document values')
    let rendered = document.source
    for (let index = document.sourceValues.length - 1; index >= 0; index -= 1) {
        const value = document.sourceValues[index]
        const marker = markers[index]
        if (!isEncryptedMarker(marker)) throw new DocumentValidationError('Replacement value is not an encrypted marker')
        const replacement = document.format === 'json' ? JSON.stringify(marker) : marker
        rendered = `${rendered.slice(0, value.start)}${replacement}${rendered.slice(value.end)}`
    }
    return rendered
}

export function canonicalSigningData(document: EncryptedDocument): string {
    return JSON.stringify({
        format: document.format,
        version: document.metadata.version,
        members: document.metadata.members,
        recipients: document.metadata.recipients,
        maintainers: document.metadata.maintainers,
        values: document.values.map(({ key, marker, jsonType }) => ({ key, marker, ...(jsonType ? { jsonType } : {}) })),
    })
}

export function validateRecipientConsistency(document: EncryptedDocument): void {
    const expected = recipientSet(document.metadata.recipients)
    for (const value of document.values) {
        const actual = recipientSet(extractAgeRecipients(value.marker))
        if (actual.size !== expected.size || [...expected].some((recipient) => !actual.has(recipient))) {
            throw new DocumentValidationError(`Recipients in ${value.key} do not match document metadata`)
        }
    }
}

export function extractAgeRecipients(marker: string): string[] {
    const payload = markerPayload(marker)
    let decoded: string
    try {
        decoded = Buffer.from(payload, 'base64url').toString('utf8')
    } catch {
        throw new DocumentValidationError('Encrypted marker has invalid base64url payload')
    }
    const lines = decoded.split(/\r?\n/u)
    if (lines[0] !== 'age-encryption.org/v1') throw new DocumentValidationError('Encrypted marker is not an age file')
    const recipients: string[] = []
    for (const line of lines.slice(1)) {
        if (line.startsWith('---')) break
        const stanza = /^-> X25519 (\S+)$/u.exec(line)
        if (stanza) recipients.push(ageRecipientFromStanza(stanza[1]))
    }
    if (recipients.length === 0) throw new DocumentValidationError('Encrypted marker has no X25519 recipients')
    if (recipientSet(recipients).size !== recipients.length) throw new DocumentValidationError('Encrypted marker has duplicate recipients')
    return recipients
}

export function isEncryptedMarker(value: string): boolean {
    return markerPattern.test(value)
}

function createParsedDocument(format: DocumentFormat, source: string, partial: Partial<DocumentMetadata>, values: SourceValue[]): ParsedDocument {
    const metadata = validateMetadata(partial)
    return { format, source, metadata, values, sourceValues: values }
}

function parseDotenvMarker(rawValue: string): { value: string, start: number, end: number } | undefined {
    const match = /^(?:"(ENC\[age:[A-Za-z0-9_-]+\])"|'(ENC\[age:[A-Za-z0-9_-]+\])'|(ENC\[age:[A-Za-z0-9_-]+\]))\s*(?:#.*)?$/u.exec(rawValue)
    if (!match) return undefined
    const value = match[1] ?? match[2] ?? match[3]
    const start = rawValue.indexOf(value)
    return { value, start, end: start + value.length }
}

function parseJsonMetadata(value: unknown): DocumentMetadata {
    if (!isRecord(value) || Array.isArray(value)) throw new DocumentValidationError('$gcrypt metadata must be an object')
    for (const key of Object.keys(value)) {
        if (!metadataKeys.has(key)) throw new DocumentValidationError(`Unknown $gcrypt metadata field ${key}`)
    }
    if (value.warning !== undefined && value.warning !== 'Do not manually edit this file. Use gcrypt instead.') {
        throw new DocumentValidationError('Invalid $gcrypt warning')
    }
    return validateMetadata({
        version: value.version === 2 ? 2 : undefined,
        members: Array.isArray(value.members) ? value.members.map(parseJsonMember) : undefined,
        recipients: Array.isArray(value.recipients) ? value.recipients as string[] : undefined,
        maintainers: Array.isArray(value.maintainers) ? value.maintainers as string[] : undefined,
        signatures: Array.isArray(value.signatures) ? value.signatures as string[] : undefined,
    })
}

function validateMetadata(partial: Partial<DocumentMetadata>): DocumentMetadata {
    if (partial.version !== 2) throw new DocumentValidationError('Missing or unsupported gcrypt version')
    const members = validateMembers(partial.members)
    const recipients = validateStringList(partial.recipients, 'recipients')
    const maintainers = validateStringList(partial.maintainers, 'maintainers')
    const signatures = validateStringList(partial.signatures, 'signatures', true)
    const memberRecipients = members.map(({ recipient }) => recipient)
    const memberMaintainers = members.flatMap(({ signingKey, isMaintainer }) => isMaintainer ? [signingKey] : [])
    if (!sameList(recipients, memberRecipients)) throw new DocumentValidationError('gcrypt recipients metadata does not match members')
    if (!sameList(maintainers, memberMaintainers)) throw new DocumentValidationError('gcrypt maintainers metadata does not match members')
    return { version: 2, members, recipients, maintainers, signatures }
}

function validateMembers(members: DocumentMember[] | undefined): DocumentMember[] {
    if (!members || members.length === 0) throw new DocumentValidationError('Missing gcrypt members metadata')
    const ids = new Set<string>()
    const recipients = new Set<string>()
    const signingKeys = new Set<string>()
    return members.map((member) => {
        if (!isRecord(member) || Object.keys(member).length !== 4 || Object.keys(member).some((key) => !['id', 'recipient', 'signingKey', 'isMaintainer'].includes(key))) {
            throw new DocumentValidationError('Invalid gcrypt member metadata')
        }
        if (typeof member.id !== 'string' || member.id === '' || /\s/u.test(member.id) || ids.has(member.id)) {
            throw new DocumentValidationError('Invalid or duplicate gcrypt member id')
        }
        if (typeof member.recipient !== 'string' || member.recipient.trim() === '' || /\s/u.test(member.recipient) || recipients.has(member.recipient)) {
            throw new DocumentValidationError('Invalid or duplicate gcrypt member recipient')
        }
        if (typeof member.signingKey !== 'string' || member.signingKey.trim() === '' || /\s/u.test(member.signingKey) || signingKeys.has(member.signingKey)) {
            throw new DocumentValidationError('Invalid or duplicate gcrypt member signing key')
        }
        if (typeof member.isMaintainer !== 'boolean') throw new DocumentValidationError('Invalid gcrypt member maintainer role')
        ids.add(member.id)
        recipients.add(member.recipient)
        signingKeys.add(member.signingKey)
        try {
            validateAgeRecipient(member.recipient)
            validateSigningPublicKey(member.signingKey)
        } catch {
            throw new DocumentValidationError('Invalid gcrypt member key metadata')
        }
        return { id: member.id, recipient: member.recipient, signingKey: member.signingKey, isMaintainer: member.isMaintainer }
    })
}

function validateStringList(values: string[] | undefined, name: string, allowEmpty = false): string[] {
    if (!values || (!allowEmpty && values.length === 0)) throw new DocumentValidationError(`Missing gcrypt ${name} metadata`)
    if (values.some((value) => typeof value !== 'string' || value.trim() === '' || /[\s,]/u.test(value))) {
        throw new DocumentValidationError(`Invalid gcrypt ${name} metadata`)
    }
    if (new Set(values).size !== values.length) throw new DocumentValidationError(`Duplicate gcrypt ${name} metadata`)
    return [...values]
}

function splitMetadataList(value: string, name: string): string[] {
    if (value === '') throw new DocumentValidationError(`Missing gcrypt ${name} metadata`)
    return value.split(',')
}

function parseDotenvMember(value: string): DocumentMember {
    const fields = value.split(',')
    if (fields.length !== 4) throw new DocumentValidationError('Invalid gcrypt member metadata')
    const [id, recipient, signingKey, isMaintainer] = fields
    if (isMaintainer !== 'true' && isMaintainer !== 'false') throw new DocumentValidationError('Invalid gcrypt member metadata')
    return { id, recipient, signingKey, isMaintainer: isMaintainer === 'true' }
}

function parseJsonMember(value: unknown): DocumentMember {
    if (!isRecord(value) || Array.isArray(value)) throw new DocumentValidationError('Invalid gcrypt member metadata')
    return {
        id: value.id as string,
        recipient: value.recipient as string,
        signingKey: value.signingKey as string,
        isMaintainer: value.isMaintainer as boolean,
    }
}

function sameList(left: string[], right: string[]): boolean {
    return left.length === right.length && left.every((value, index) => value === right[index])
}

function markerPayload(marker: string): string {
    const match = markerPattern.exec(marker)
    if (!match) throw new DocumentValidationError('Invalid encrypted marker')
    return match[1]
}

function recipientSet(recipients: string[]): Set<string> {
    if (new Set(recipients).size !== recipients.length) throw new DocumentValidationError('Duplicate recipients')
    return new Set(recipients)
}

// age files encode X25519 recipient bytes in the stanza; metadata uses bech32 age1 keys.
function ageRecipientFromStanza(stanza: string): string {
    if (stanza.startsWith('age1')) return stanza // Supports readable fixture files as well.
    let bytes: Buffer
    try { bytes = Buffer.from(stanza, 'base64') } catch { throw new DocumentValidationError('Encrypted marker has an invalid X25519 recipient') }
    if (bytes.length !== 32) throw new DocumentValidationError('Encrypted marker has an invalid X25519 recipient')
    const data = convertBits([...bytes], 8, 5)
    const checksumInput = [...bech32Prefix('age'), ...data]
    return `age1${data.map((word) => 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'[word]).join('')}${bech32Checksum(checksumInput).map((word) => 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'[word]).join('')}`
}

function convertBits(values: number[], from: number, to: number): number[] {
    let accumulator = 0
    let bits = 0
    const output: number[] = []
    for (const value of values) {
        accumulator = (accumulator << from) | value
        bits += from
        while (bits >= to) { bits -= to; output.push((accumulator >> bits) & 31) }
    }
    if (bits > 0) output.push((accumulator << (to - bits)) & 31)
    return output
}

function bech32Prefix(prefix: string): number[] { return [...prefix].map((character) => character.charCodeAt(0) >> 5).concat(0, [...prefix].map((character) => character.charCodeAt(0) & 31)) }
function bech32Checksum(words: number[]): number[] {
    let value = 1
    for (const word of [...words, 0, 0, 0, 0, 0, 0]) value = bech32Polymod(value) ^ word
    value ^= 1
    return [5, 4, 3, 2, 1, 0].map((shift) => (value >> (shift * 5)) & 31)
}
function bech32Polymod(value: number): number {
    const top = value >>> 25
    let result = (value & 0x1ffffff) << 5
    for (const [index, generator] of [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3].entries()) if ((top >> index) & 1) result ^= generator
    return result
}

function ensureUniqueKeys(values: EncryptedValue[]): void {
    if (new Set(values.map(({ key }) => key)).size !== values.length) throw new DocumentValidationError('Duplicate document keys are not supported')
}

function isRecord(value: unknown): value is Record<string, unknown> {
    return typeof value === 'object' && value !== null
}

class JsonObjectScanner {
    private position = 0

    constructor(private readonly source: string) {}

    *properties(): Generator<{ key: string, value: string, type: JsonScalarType | 'object' | 'array', start: number, end: number }> {
        this.skipWhitespace()
        this.expect('{')
        this.skipWhitespace()
        if (this.peek() === '}') return
        while (true) {
            const key = this.readString()
            this.skipWhitespace()
            this.expect(':')
            this.skipWhitespace()
            const start = this.position
            const { value, type } = this.readValue()
            const end = this.position
            yield { key, value, type, start, end }
            this.skipWhitespace()
            if (this.peek() === '}') return
            this.expect(',')
            this.skipWhitespace()
        }
    }

    private readValue(): { value: string, type: JsonScalarType | 'object' | 'array' } {
        if (this.peek() === '"') return { value: this.readString(), type: 'string' }
        if (this.source.startsWith('true', this.position)) { this.position += 4; return { value: 'true', type: 'boolean' } }
        if (this.source.startsWith('false', this.position)) { this.position += 5; return { value: 'false', type: 'boolean' } }
        if (this.source.startsWith('null', this.position)) { this.position += 4; return { value: 'null', type: 'null' } }
        if (this.peek() === '{' || this.peek() === '[') {
            const type = this.peek() === '{' ? 'object' : 'array'
            return { value: this.readCompound(), type }
        }
        const match = /-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/u.exec(this.source.slice(this.position))
        if (!match) throw new DocumentValidationError('Invalid JSON value')
        this.position += match[0].length
        return { value: match[0], type: 'number' }
    }

    private readCompound(): string {
        const start = this.position
        const open = this.source[this.position]
        const close = open === '{' ? '}' : ']'
        let depth = 0
        do {
            const character = this.source[this.position]
            if (character === '"') this.readString()
            else {
                this.position += 1
                if (character === open) depth += 1
                if (character === close) depth -= 1
            }
        } while (depth > 0 && this.position < this.source.length)
        return this.source.slice(start, this.position)
    }

    private readString(): string {
        const start = this.position
        this.expect('"')
        while (this.position < this.source.length) {
            const character = this.source[this.position]
            this.position += 1
            if (character === '\\') this.position += 1
            else if (character === '"') {
                try { return JSON.parse(this.source.slice(start, this.position)) as string } catch { throw new DocumentValidationError('Invalid JSON string') }
            }
        }
        throw new DocumentValidationError('Unterminated JSON string')
    }

    private skipWhitespace(): void { while (/\s/u.test(this.peek())) this.position += 1 }
    private peek(): string { return this.source[this.position] ?? '' }
    private expect(character: string): void {
        if (this.peek() !== character) throw new DocumentValidationError('Invalid JSON document')
        this.position += 1
    }
}
import { validateAgeRecipient, validateSigningPublicKey } from './crypto.js'
