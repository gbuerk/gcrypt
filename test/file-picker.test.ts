import { mkdir, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import { findEncryptedFiles } from '../src/index.js'

const temporaryDirectories: string[] = []

async function createTemporaryDirectory(): Promise<string> {
    const directory = join(tmpdir(), `gcrypt-picker-${Date.now()}-${Math.random()}`)
    temporaryDirectories.push(directory)
    await mkdir(directory, { recursive: true })
    return directory
}

afterEach(async () => {
    await Promise.all(temporaryDirectories.splice(0).map((directory) => rm(directory, { force: true, recursive: true })))
})

describe('findEncryptedFiles', () => {
    it('lists encrypted files recursively while ignoring Git and dependencies', async () => {
        const directory = await createTemporaryDirectory()
        await mkdir(join(directory, 'config'), { recursive: true })
        await mkdir(join(directory, '.git'), { recursive: true })
        await mkdir(join(directory, 'node_modules', 'example'), { recursive: true })
        await writeFile(join(directory, '.env.dev.enc'), '')
        await writeFile(join(directory, 'config', 'prod.env.enc'), '')
        await writeFile(join(directory, '.git', 'ignored.env.enc'), '')
        await writeFile(join(directory, 'node_modules', 'example', 'ignored.env.enc'), '')

        await expect(findEncryptedFiles(directory)).resolves.toEqual(['.env.dev.enc', 'config/prod.env.enc'])
    })
})
