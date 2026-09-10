import { validateAgeRecipient, validateSigningPublicKey } from './crypto.js'

const prefix = 'gcrypt-member-v1.'

export interface MemberSetupCode {
    recipient: string
    signingKey: string
}

export function encodeMemberSetupCode({ recipient, signingKey }: MemberSetupCode): string {
    validateAgeRecipient(recipient)
    validateSigningPublicKey(signingKey)
    return `${prefix}${Buffer.from(JSON.stringify({ recipient, signingKey })).toString('base64url')}`
}

export function decodeMemberSetupCode(value: string): MemberSetupCode {
    try {
        const code = value.trim()
        if (!code.startsWith(prefix)) throw new Error()
        const encoded = code.slice(prefix.length)
        if (!/^[A-Za-z0-9_-]+$/u.test(encoded) || Buffer.from(encoded, 'base64url').toString('base64url') !== encoded) throw new Error()
        const parsed: unknown = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8'))
        if (!isMemberSetupCode(parsed)) throw new Error()
        validateAgeRecipient(parsed.recipient)
        validateSigningPublicKey(parsed.signingKey)
        if (encodeMemberSetupCode(parsed) !== code) throw new Error()
        return parsed
    } catch {
        throw new Error('Invalid member setup code')
    }
}

function isMemberSetupCode(value: unknown): value is MemberSetupCode {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) return false
    const record = value as Record<string, unknown>
    const entries = Object.entries(record)
    return entries.length === 2
        && typeof record.recipient === 'string'
        && typeof record.signingKey === 'string'
        && entries.every(([key]) => key === 'recipient' || key === 'signingKey')
}
