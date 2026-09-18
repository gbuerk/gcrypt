# @gbuerk/gcrypt

Store encrypted, signed `.env` and JSON configuration in Git. `gcrypt` uses
[age](https://age-encryption.org/) encryption and Node.js cryptography, so it
does not require an installed `age` binary.

Each team member has a decryption key and a signing key. A listed maintainer
must sign every version before `gcrypt` will decrypt or change it.

## Requirements

- Node.js 22.13 or later (Node 23 requires 23.5 or later)
- A Git repository for the encrypted configuration file

## Install

Install `gcrypt` in the project that owns the configuration:

```bash
npm install --save-dev @gbuerk/gcrypt
npx gcrypt init
```

`init` creates `.env.dev.enc`, adds helper scripts to `package.json`, and
wraps the existing `dev` script. It asks before replacing any existing scripts.

The private keys are stored locally at:

```text
~/.config/gcrypt/keys/default.txt
~/.config/gcrypt/signing/default.txt
```

Never commit, share, or copy these private keys. Add the generated
`.env.dev.enc` to Git; it contains encrypted values and public team metadata.

## Team workflow

### 1. Set up a new member

Each developer runs this once from the project:

```bash
npm run dev:setup
```

The command prints a versioned member setup code. Send that code and a stable,
human-readable member ID, such as `alice-smith`, to a maintainer. The setup
code contains only public keys.

### 2. Grant access

A maintainer grants the new member access, then commits the changed encrypted
file:

```bash
npm run secrets:grant -- .env.dev.enc
```

### 3. Edit configuration

Listed maintainers edit a file using the editor named by `VISUAL` or `EDITOR`:

```bash
export EDITOR=vim
npm run secrets -- .env.dev.enc
```

`gcrypt` verifies maintainer approval before it writes a temporary plaintext
file. An unchanged edit does not rewrite the encrypted file; otherwise it
re-encrypts only added or changed values and signs the updated document.

### 4. Run the application

After `gcrypt init`, use the normal development command:

```bash
npm run dev
```

The decrypted dotenv values exist only in the environment of the application
child process.

## Access management

Remove a member's full access and re-encrypt every value for the remaining
members:

```bash
npm run secrets:revoke -- .env.dev.enc
```

To retain decryption access but remove approval rights, demote the member:

```bash
npm run secrets:maintainer:revoke -- .env.dev.enc
```

Promote an existing member to maintainer:

```bash
npm run secrets:maintainer:grant -- .env.dev.enc
```

Verify signatures and metadata without decrypting:

```bash
npm run secrets:verify -- .env.dev.enc
```

Removing a recipient protects future versions only. Rotate any credentials the
former member may already know.

## JSON files

Create a JSON configuration file by using a `.json.enc` name:

```bash
npx gcrypt secrets init config.json.enc
```

JSON documents support nested objects and arrays. Every scalar leaf (strings,
numbers, booleans, and `null`) is encrypted independently. The complete JSON
shape, including empty objects and arrays, is included in the signature.

## Commands

```text
gcrypt init [file]                 Initialize a project and encrypted dotenv file
gcrypt setup                       Create or show the local member setup code
gcrypt grant [file]                Add a member from their setup code
gcrypt revoke [file]               Remove a member's access
gcrypt maintainer grant [file]     Give an existing member approval rights
gcrypt maintainer revoke [file]    Remove an existing member's approval rights
gcrypt verify [file]               Verify without decrypting
gcrypt decrypt [file]              Print plaintext to standard output
gcrypt edit [file]                 Edit and re-encrypt a file
gcrypt exec <file> -- <command>    Run a command with decrypted dotenv values
gcrypt secrets init [file]         Create an encrypted dotenv or JSON file
```

When the file argument is omitted in an interactive terminal, `gcrypt` offers
encrypted files found below the current directory.

## Security model

- Values are encrypted independently for all current recipients using age
  X25519 recipients.
- Document metadata and encrypted values are signed with Ed25519 keys.
- Any listed maintainer may approve a version; at least one valid maintainer
  signature is required.
- Public member IDs, recipients, signing keys, and roles are stored in the
  encrypted file's metadata so the team can review access changes in Git.

`gcrypt` does not protect secrets that have already been decrypted, copied, or
committed in prior Git history. Use normal credential rotation and access
controls alongside this tool.

## Publishing

This repository does not commit `dist/`. `npm pack` and `npm publish` run the
TypeScript build through the `prepack` lifecycle script, and the package ships
only the generated `dist/` directory plus standard npm files such as this
README and the license.

## License

[MIT](LICENSE)
