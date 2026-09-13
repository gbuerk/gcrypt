import { access, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { spawn } from 'node:child_process'
import { afterEach, describe, expect, it } from 'vitest'
import { parseEncryptedDocument } from '../src/document.js'

const temporaryDirectories: string[] = []

async function temporaryDirectory(): Promise<string> {
    const directory = await mkdtemp(join(tmpdir(), 'gcrypt-init-'))
    temporaryDirectories.push(directory)
    return directory
}

afterEach(async () => {
    await Promise.all(temporaryDirectories.splice(0).map((directory) => rm(directory, { force: true, recursive: true })))
})

describe('gcrypt package', () => {
    it('generates the secrets:revoke package script during init', async () => {
        const project = await temporaryDirectory()
        const home = await temporaryDirectory()
        const packageRoot = process.cwd()
        await writeFile(join(project, 'package.json'), JSON.stringify({
            name: 'test-project',
            scripts: { dev: 'vite' },
            devDependencies: { '@gbuerk/gcrypt': 'workspace:*' },
        }))

        let standardError = ''
        let standardOutput = ''
        const status = await new Promise<number | null>((resolve, reject) => {
            const child = spawn(process.execPath, ['--import', join(packageRoot, 'node_modules', 'tsx', 'dist', 'loader.mjs'), join(packageRoot, 'src', 'index.ts'), 'init'], {
                cwd: project,
                env: { ...process.env, HOME: home },
                stdio: ['pipe', 'pipe', 'pipe'],
            })
            child.once('error', reject)
            child.once('exit', resolve)
            child.stderr.on('data', (chunk: Buffer) => { standardError += chunk.toString() })
            let confirmationsSent = 0
            let memberIdSent = false
            child.stdout.on('data', (chunk: Buffer) => {
                standardOutput += chunk.toString()
                const confirmations = standardOutput.match(/\[[Yy]\/[Nn]\]/gu)?.length ?? 0
                while (confirmationsSent < confirmations) {
                    child.stdin.write(confirmationsSent === 0 ? '\n' : 'y\n')
                    confirmationsSent += 1
                }
                if (confirmationsSent === 3 && standardOutput.includes('Run npm run secrets')) {
                    child.stdin.end()
                }
                if (!memberIdSent && standardOutput.includes('Initial maintainer ID:')) {
                    child.stdin.write('test-maintainer\n')
                    memberIdSent = true
                }
            })
        })

        expect(status, standardError).toBe(0)
        const packageJson = JSON.parse(await readFile(join(project, 'package.json'), 'utf8')) as { scripts: Record<string, string> }
        expect(packageJson.scripts['secrets:revoke']).toBe('gcrypt revoke')
        expect(packageJson.scripts['dev:setup']).toBe('gcrypt setup')
        expect(standardOutput).toContain('private access key (never share)')
        expect(standardOutput).toContain('private signing key (never share)')
        expect(standardOutput).not.toContain('Share this member setup code with a maintainer')
        expect(standardOutput).toContain('Run npm run secrets to add values.')
        await expect(access(join(project, '.env.example'))).rejects.toMatchObject({ code: 'ENOENT' })
        expect(parseEncryptedDocument(await readFile(join(project, '.env.dev.enc'), 'utf8'), 'dotenv').metadata.members).toMatchObject([
            { id: 'test-maintainer', recipient: expect.stringMatching(/^age1/u), signingKey: expect.stringMatching(/^ed25519:/u), isMaintainer: true },
        ])
    })

    it('initializes an empty version-3 JSON document', async () => {
        const project = await temporaryDirectory()
        const home = await temporaryDirectory()
        const packageRoot = process.cwd()
        let standardError = ''
        let standardOutput = ''
        const status = await new Promise<number | null>((resolve, reject) => {
            const child = spawn(process.execPath, ['--import', join(packageRoot, 'node_modules', 'tsx', 'dist', 'loader.mjs'), join(packageRoot, 'src', 'index.ts'), 'secrets', 'init', 'settings.json.enc'], {
                cwd: project,
                env: { ...process.env, HOME: home },
                stdio: ['pipe', 'pipe', 'pipe'],
            })
            child.once('error', reject)
            child.once('exit', resolve)
            child.stderr.on('data', (chunk: Buffer) => { standardError += chunk.toString() })
            child.stdout.on('data', (chunk: Buffer) => {
                standardOutput += chunk.toString()
                if (standardOutput.includes('Initial maintainer ID:')) child.stdin.end('test-maintainer\n')
            })
        })

        expect(status, standardError).toBe(0)
        expect(standardOutput).not.toContain('Share this member setup code with a maintainer')
        const document = parseEncryptedDocument(await readFile(join(project, 'settings.json.enc'), 'utf8'), 'json')
        expect(document.metadata.version).toBe(3)
        expect(document.values).toEqual([])
    })
})
