#!/usr/bin/env node

import { realpathSync } from 'node:fs'
import { access, mkdir, readdir, readFile, writeFile } from 'node:fs/promises'
import { createInterface } from 'node:readline/promises'
import { stdin, stdout } from 'node:process'
import { fileURLToPath } from 'node:url'
import { dirname, join, relative, sep } from 'node:path'
import { Command } from 'commander'
import inquirer from 'inquirer'
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
    verifyEncryptedDocument,
} from './commands.js'
import { parseEncryptedDocument, type DocumentMember } from './document.js'

interface Prompt {
    ask(question: string): Promise<string>
    confirm(question: string, defaultValue?: boolean): Promise<boolean>
    close(): void
}

function terminalPrompt(): Prompt {
    const readline = createInterface({ input: stdin, output: stdout })
    return {
        ask: (question) => readline.question(question),
        async confirm(question, defaultValue = false) {
            const answer = (await readline.question(`${question} ${defaultValue ? '[Y/n]' : '[y/N]'} `)).trim()
            return answer === '' ? defaultValue : /^(y|yes)$/iu.test(answer)
        },
        close: () => readline.close(),
    }
}

async function selectedFile(file: string | undefined, getPrompt: () => Prompt): Promise<string> {
    if (file) return file
    const files = await findEncryptedFiles()
    if (files.length > 0 && stdin.isTTY) {
        const manual = '__gcrypt_manual_path__'
        const { selected } = await inquirer.prompt<{ selected: string }>([
            {
                type: 'select',
                name: 'selected',
                message: 'Select an encrypted file:',
                pageSize: 12,
                choices: [
                    ...files.map((candidate) => ({ name: candidate, value: candidate })),
                    new inquirer.Separator(),
                    { name: 'Enter a path manually', value: manual },
                ],
            },
        ])
        if (selected !== manual) return selected
    }

    const value = (await getPrompt().ask('Encrypted file path: ')).trim()
    if (!value) throw new Error('An encrypted file path is required')
    if (!value.endsWith('.enc')) throw new Error('Encrypted files must end in .enc')
    return value
}

async function selectedMemberId(filePath: string, message: string, eligible: (member: DocumentMember) => boolean): Promise<string> {
    const source = await readFile(filePath, 'utf8')
    const format = source.trimStart().startsWith('{') ? 'json' : 'dotenv'
    const members = parseEncryptedDocument(source, format).metadata.members.filter(eligible)
    if (members.length === 0) throw new Error('No eligible members are listed')
    const { memberId } = await inquirer.prompt<{ memberId: string }>([
        {
            type: 'select',
            name: 'memberId',
            message,
            pageSize: 12,
            choices: members.map((member) => ({ name: `${member.id} (${member.recipient})`, value: member.id })),
        },
    ])
    return memberId
}

export async function findEncryptedFiles(rootDirectory = process.cwd()): Promise<string[]> {
    const files: string[] = []
    const ignoredDirectories = new Set(['.git', 'node_modules'])

    async function visit(directory: string): Promise<void> {
        const entries = await readdir(directory, { withFileTypes: true })
        await Promise.all(entries.map(async (entry) => {
            const filePath = join(directory, entry.name)
            if (entry.isDirectory() && !ignoredDirectories.has(entry.name)) await visit(filePath)
            else if (entry.isFile() && entry.name.endsWith('.enc')) files.push(relative(rootDirectory, filePath))
        }))
    }

    await visit(rootDirectory)
    return files.sort((left, right) => left.localeCompare(right))
}

function reportPrivateKey(result: { created: boolean, path: string }, identity: string): void {
    stdout.write(`${result.created ? 'Created' : 'Using'} private ${identity} (never share) at ${result.path}\n`)
}

async function runSetup(): Promise<Awaited<ReturnType<typeof setup>>> {
    const result = await setup()
    reportPrivateKey(result.age, 'access key')
    reportPrivateKey(result.signing, 'signing key')
    stdout.write(`Share this member setup code with a maintainer:\n${result.memberSetupCode}\n`)
    return result
}

async function runMaintainerSetup(): Promise<void> {
    reportPrivateKey(await maintainerSetup(), 'signing key')
}

async function initialMemberId(prompt: Prompt): Promise<string> {
    const memberId = (await prompt.ask('Initial maintainer ID: ')).trim()
    if (!memberId || /\s/u.test(memberId)) throw new Error('Initial maintainer ID must be a non-empty string without whitespace')
    return memberId
}

async function initializeProject(file: string | undefined, getPrompt: () => Prompt): Promise<void> {
    const packagePath = join(process.cwd(), 'package.json')
    let packageJson: { scripts?: Record<string, string>, dependencies?: Record<string, string>, devDependencies?: Record<string, string> }
    try { packageJson = JSON.parse(await readFile(packagePath, 'utf8')) as { scripts?: Record<string, string>, dependencies?: Record<string, string>, devDependencies?: Record<string, string> } } catch { throw new Error('init requires package.json in the current directory') }
    const target = file ?? '.env.dev.enc'
    if (!target.endsWith('.enc')) throw new Error('Encrypted files must end in .enc')
    try { await access(target); throw new Error(`Refusing to overwrite existing encrypted file: ${target}`) } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error }
    const scripts = { ...packageJson.scripts }
    if (scripts.dev) {
        const prompt = getPrompt()
        if (!await prompt.confirm(`Move the current dev command to dev:app exactly as written?\n${scripts.dev}`, true)) throw new Error('init cancelled')
        if (scripts['dev:app'] && !await prompt.confirm('Replace existing dev:app script?')) throw new Error('init cancelled')
        scripts['dev:app'] = scripts.dev
    } else {
        const prompt = getPrompt()
        const command = (await prompt.ask('Project development command: ')).trim()
        if (!command) throw new Error('A project development command is required')
        scripts['dev:app'] = command
    }
    scripts.dev = 'node scripts/dev.mjs'
    for (const [name, command] of Object.entries({ 'dev:setup': 'gcrypt setup', secrets: 'gcrypt edit', 'secrets:grant': 'gcrypt grant', 'secrets:revoke': 'gcrypt revoke', 'secrets:maintainer:grant': 'gcrypt maintainer grant', 'secrets:maintainer:revoke': 'gcrypt maintainer revoke', 'secrets:init': 'gcrypt secrets init', 'secrets:verify': 'gcrypt verify' })) {
        if (!scripts[name]) scripts[name] = command
        else if (scripts[name] !== command && await getPrompt().confirm(`Replace existing ${name} script?`)) scripts[name] = command
    }
    packageJson.scripts = scripts
    await mkdir(join(process.cwd(), 'scripts'), { recursive: true })
    await writeFile(join(process.cwd(), 'scripts', 'dev.mjs'), `import { spawn } from 'node:child_process'\n\nconst child = spawn('gcrypt', ['exec', ${JSON.stringify(target)}, '--', 'npm', 'run', 'dev:app'], { stdio: 'inherit' })\nchild.on('exit', (code) => process.exit(code ?? 1))\n`)
    await writeFile(packagePath, `${JSON.stringify(packageJson, undefined, 2)}\n`)
    if (!packageJson.dependencies?.['@gbuerk/gcrypt'] && !packageJson.devDependencies?.['@gbuerk/gcrypt']) {
        await installGcrypt(localPackageSource())
    }
    const identities = await runSetup()
    const memberId = await initialMemberId(getPrompt())
    const examplePath = '.env.example'
    try { await access(examplePath) } catch { await writeFile(examplePath, '') }
    await createEncryptedDocument(target, emptyDocument(target), {
        members: [{ id: memberId, recipient: identities.age.recipient, signingKey: identities.signing.publicKey, isMaintainer: true }],
    })
    stdout.write(`Created ${target}. Run npm run secrets to add values.\n`)
}

async function installGcrypt(source?: string): Promise<void> {
    const packageManager = await exists('pnpm-lock.yaml') ? 'pnpm' : await exists('yarn.lock') ? 'yarn' : 'npm'
    const packageReference = source ?? '@gbuerk/gcrypt'
    const arguments_ = packageManager === 'yarn' ? ['add', '--dev', packageReference] : ['install', '--save-dev', packageReference]
    const status = await new Promise<number | null>((resolve, reject) => {
        const child = spawn(packageManager, arguments_, { stdio: 'inherit' })
        child.once('error', reject)
        child.once('exit', resolve)
    })
    if (status !== 0) throw new Error(`${packageManager} failed to install @gbuerk/gcrypt`)
}

async function exists(path: string): Promise<boolean> { try { await access(path); return true } catch { return false } }

function localPackageSource(): string | undefined {
    const packageRoot = join(dirname(fileURLToPath(import.meta.url)), '..')
    return packageRoot.includes(`${sep}node_modules${sep}`) ? undefined : packageRoot
}

export function createProgram(providedPrompt?: Prompt): Command {
    let prompt = providedPrompt
    const getPrompt = (): Prompt => {
        prompt ??= terminalPrompt()
        return prompt
    }
    const program = new Command()
    program.name('gcrypt').description('Safely share app settings with your team').version('0.1.3').exitOverride()
    program.hook('postAction', () => { prompt?.close() })
    program.command('setup').description('Set up your local access and signing keys').action(async () => { await runSetup() })
    const maintainer = program.command('maintainer').description('Manage who can approve changes')
    maintainer.command('setup').action(() => runMaintainerSetup())
    maintainer.command('grant [file]').action(async (file) => {
        const selected = await selectedFile(file, getPrompt)
        await grantMaintainer(selected, {
            prompt: {
                memberId: () => selectedMemberId(selected, 'Select a member who can approve changes:', (member) => !member.isMaintainer),
            },
        })
    })
    maintainer.command('revoke [file]').action(async (file) => {
        const selected = await selectedFile(file, getPrompt)
        await revokeMaintainer(selected, { prompt: { memberId: () => selectedMemberId(selected, 'Select a member who can no longer approve changes:', (member) => member.isMaintainer) } })
    })
    program.command('grant [file]').action(async (file) => {
        const selected = await selectedFile(file, getPrompt)
        const activePrompt = getPrompt()
        await grantRecipient(selected, { prompt: { memberId: () => activePrompt.ask('Member ID: '), memberSetupCode: () => activePrompt.ask('Member setup code: ') } })
    })
    program.command('revoke [file]').action(async (file) => {
        const selected = await selectedFile(file, getPrompt)
        await revokeRecipient(selected, { prompt: { memberId: () => selectedMemberId(selected, 'Select a member to revoke:', () => true) } })
    })
    program.command('verify [file]').action(async (file) => {
        await verifyEncryptedDocument(await selectedFile(file, getPrompt))
        stdout.write('This file is valid and has maintainer approval.\n')
    })
    program.command('decrypt [file]').action(async (file) => {
        stdout.write(await decryptEncryptedDocument(await selectedFile(file, getPrompt)))
    })
    program.command('edit [file]').action(async (file) => {
        const selected = await selectedFile(file, getPrompt)
        const editor = process.env.VISUAL || process.env.EDITOR
        if (!editor) throw new Error('Set VISUAL or EDITOR to edit secrets')
        await editEncryptedDocument(selected, editor)
    })
    program.command('exec <file> [command...]').allowUnknownOption().action(async (file, command) => {
        const status = await executeDotenv(file, command, undefined)
        process.exitCode = status
    })
    program.command('init [file]').action((file) => initializeProject(file, getPrompt))
    const secrets = program.command('secrets').description('Manage encrypted secrets')
    secrets.command('init [file]').action(async (file) => {
        const target = file ?? '.env.dev.enc'
        try { await access(target); throw new Error(`Refusing to overwrite existing encrypted file: ${target}`) } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error }
        const identities = await runSetup()
        await createEncryptedDocument(target, emptyDocument(target), {
            members: [{ id: await initialMemberId(getPrompt()), recipient: identities.age.recipient, signingKey: identities.signing.publicKey, isMaintainer: true }],
        })
        stdout.write(`Created ${target}. Run npm run secrets to add values.\n`)
    })
    return program
}

function emptyDocument(filePath: string): string {
    return filePath.endsWith('.json.enc') || filePath.endsWith('.json') ? '{}' : ''
}

async function main(): Promise<void> {
    try { await createProgram().parseAsync(process.argv) } catch (error) {
        stderr(error)
        process.exitCode = 1
    }
}

function stderr(error: unknown): void { process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`) }

function invokedAsCli(): boolean {
    if (!process.argv[1]) return false
    try {
        return realpathSync(process.argv[1]) === fileURLToPath(import.meta.url)
    } catch {
        return false
    }
}

if (invokedAsCli()) void main()
import { spawn } from 'node:child_process'
