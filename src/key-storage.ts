import { chmod, mkdir, readFile, stat, writeFile } from 'node:fs/promises'
import { homedir } from 'node:os'
import { dirname, join } from 'node:path'

const configDirectoryName = '.config/gcrypt'

export function defaultAgeIdentityPath(homeDirectory = homedir()): string {
    return join(homeDirectory, configDirectoryName, 'keys', 'default.txt')
}

export function defaultSigningIdentityPath(homeDirectory = homedir()): string {
    return join(homeDirectory, configDirectoryName, 'signing', 'default.txt')
}

export async function writeDefaultAgeIdentity(identity: string, homeDirectory = homedir()): Promise<string> {
    return writePrivateKey(defaultAgeIdentityPath(homeDirectory), identity)
}

export async function readDefaultAgeIdentity(homeDirectory = homedir()): Promise<string> {
    return readPrivateKey(defaultAgeIdentityPath(homeDirectory))
}

export async function writeDefaultSigningIdentity(identity: string, homeDirectory = homedir()): Promise<string> {
    return writePrivateKey(defaultSigningIdentityPath(homeDirectory), identity)
}

export async function readDefaultSigningIdentity(homeDirectory = homedir()): Promise<string> {
    return readPrivateKey(defaultSigningIdentityPath(homeDirectory))
}

async function writePrivateKey(filePath: string, value: string): Promise<string> {
    const configDirectory = dirname(dirname(filePath))
    const directory = dirname(filePath)
    await mkdir(configDirectory, { mode: 0o700, recursive: true })
    await chmod(configDirectory, 0o700)
    await mkdir(directory, { mode: 0o700, recursive: true })
    await chmod(directory, 0o700)
    await writeFile(filePath, `${value}\n`, { encoding: 'utf8', mode: 0o600 })
    await chmod(filePath, 0o600)
    return filePath
}

async function readPrivateKey(filePath: string): Promise<string> {
    const fileStatus = await stat(filePath)
    if ((fileStatus.mode & 0o077) !== 0) {
        throw new Error(`Refusing group- or world-readable private key file: ${filePath}`)
    }
    return (await readFile(filePath, 'utf8')).trim()
}
