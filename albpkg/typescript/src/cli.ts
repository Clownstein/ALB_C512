/**
 * `albpkg` command line interface (Node.js).
 *
 * Passphrases are never accepted as arguments.  They come from a no-echo
 * prompt, or -- for automation -- from a file descriptor or a file named by
 * ALBPKG_PASSPHRASE_FILE, never from argv and never from a log line.
 */

import { readFileSync } from "node:fs";
import { mkdirSync } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import { VERSION } from "./index.ts";
import { ContactStore } from "./contacts.ts";
import { AlbpkgError, FormatError, PassphraseError } from "./errors.ts";
import {
  Identity,
  PublicIdentity,
  exportPublicIdentity,
  generateIdentity,
  loadIdentity,
  migrateLegacyIdentity,
  saveIdentity,
  type PassphraseProvider,
} from "./identity.ts";
import { openFile, sealFile, type ProgressHook } from "./package.ts";
import { CHUNK_SIZE, SUITE_NAME } from "./suite.ts";

interface GlobalOptions {
  home: string;
  identity?: string;
  passphraseFd?: number;
}

interface ParsedArgs extends GlobalOptions {
  command: string;
  positional: string[];
  overwrite: boolean;
  to?: string;
}

function defaultHome(): string {
  return process.env["ALBPKG_HOME"] ?? path.join(os.homedir(), ".albpkg");
}

// ---- Passphrase sourcing -------------------------------------------------

function passphraseProvider(args: GlobalOptions): PassphraseProvider | undefined {
  if (args.passphraseFd !== undefined) {
    const fd = args.passphraseFd;
    return (): string => {
      try {
        return readFileSync(fd, "utf8").split(/\r?\n/)[0] ?? "";
      } catch (cause) {
        throw new PassphraseError(`cannot read passphrase from fd ${fd}`, { cause });
      }
    };
  }

  const file = process.env["ALBPKG_PASSPHRASE_FILE"];
  if (file) {
    return (): string => {
      try {
        const first = readFileSync(file, "utf8").split(/\r?\n/)[0];
        if (first === undefined) throw new Error("empty file");
        return first;
      } catch (cause) {
        throw new PassphraseError(
          "cannot read the passphrase file named by ALBPKG_PASSPHRASE_FILE",
          { cause },
        );
      }
    };
  }

  return undefined; // interactive no-echo prompt
}

function store(args: GlobalOptions): ContactStore {
  return new ContactStore(path.join(args.home, "contacts"));
}

function identityPath(args: GlobalOptions): string {
  return args.identity ?? path.join(args.home, "identity.key");
}

function loadLocalIdentity(args: GlobalOptions): Promise<Identity> {
  return loadIdentity(identityPath(args), {
    passphraseProvider: passphraseProvider(args),
  });
}

function progressHook(label: string): ProgressHook | undefined {
  if (!process.stderr.isTTY) return undefined;
  let last = 0;
  return (done, chunks) => {
    if (chunks - last >= 16 || chunks <= 1) {
      last = chunks;
      const mib = (done / (1 << 20)).toFixed(1);
      process.stderr.write(`\r${label}: ${mib} MiB (${chunks} chunks)`);
    }
  };
}

function endProgress(): void {
  if (process.stderr.isTTY) process.stderr.write("\n");
}

// ---- Commands ------------------------------------------------------------

async function cmdGenerateIdentity(args: ParsedArgs): Promise<number> {
  const target = identityPath(args);
  mkdirSync(path.dirname(target), { recursive: true });
  const identity = generateIdentity();
  await saveIdentity(identity, target, {
    passphraseProvider: passphraseProvider(args),
    overwrite: args.overwrite,
  });
  console.log(`identity written to ${target}`);
  console.log(`suite:       ${SUITE_NAME}`);
  console.log(`fingerprint: ${identity.public.fingerprintText}`);
  console.log(
    "\nGive the full fingerprint to your contacts over a channel you already " +
      "trust.\nThey must compare all 64 characters before they can use your key.",
  );
  return 0;
}

async function cmdExportPublicIdentity(args: ParsedArgs): Promise<number> {
  const identity = await loadLocalIdentity(args);
  const target = requirePositional(args, 0, "output path");
  const fpr = exportPublicIdentity(identity, target, { overwrite: args.overwrite });
  console.log(`public identity written to ${target}`);
  console.log(`fingerprint: ${fpr}`);
  return 0;
}

async function cmdShowIdentity(args: ParsedArgs): Promise<number> {
  const identity = await loadLocalIdentity(args);
  console.log(`suite:       ${SUITE_NAME}`);
  console.log(`fingerprint: ${identity.public.fingerprintText}`);
  return 0;
}

async function cmdMigrateLegacyIdentity(args: ParsedArgs): Promise<number> {
  const source = requirePositional(args, 0, "legacy identity path");
  const target = identityPath(args);
  const identity = await migrateLegacyIdentity(source, target, {
    passphraseProvider: passphraseProvider(args),
    overwrite: args.overwrite,
  });
  console.log(`migrated identity written to ${target}`);
  console.log(`original retained at ${source}`);
  console.log(`fingerprint: ${identity.public.fingerprintText}`);
  return 0;
}

async function cmdImportContact(args: ParsedArgs): Promise<number> {
  const name = requirePositional(args, 0, "contact name");
  const file = requirePositional(args, 1, "public identity file");
  const contact = store(args).importContact(
    name,
    PublicIdentity.fromArmored(readFileSync(file, "utf8")),
  );
  console.log(`imported '${contact.name}' as ${contact.trust}`);
  console.log(`fingerprint: ${contact.fingerprintText}`);
  console.log(
    "\nThis contact is UNVERIFIED and cannot be used yet.\n" +
      "Confirm the fingerprint above with them over a separate, trusted channel,\n" +
      `then run:  albpkg verify-contact ${contact.name} <fingerprint>`,
  );
  return 0;
}

async function cmdVerifyContact(args: ParsedArgs): Promise<number> {
  const selector = requirePositional(args, 0, "contact");
  const fingerprint = requirePositional(args, 1, "fingerprint");
  const contact = store(args).verifyContact(selector, fingerprint);
  console.log(`'${contact.name}' is now verified`);
  console.log(`fingerprint: ${contact.fingerprintText}`);
  return 0;
}

async function cmdListContacts(args: ParsedArgs): Promise<number> {
  const contacts = store(args).list();
  if (contacts.length === 0) {
    console.log("no contacts");
    return 0;
  }
  const width = Math.max(...contacts.map((contact) => contact.name.length));
  for (const contact of contacts) {
    console.log(
      `${contact.name.padEnd(width)}  ${contact.trust.padEnd(10)}  ${contact.fingerprintText}`,
    );
  }
  return 0;
}

async function cmdRevokeContact(args: ParsedArgs): Promise<number> {
  const contact = store(args).revoke(requirePositional(args, 0, "contact"));
  console.log(`'${contact.name}' is revoked and will be rejected from now on`);
  return 0;
}

async function cmdSeal(args: ParsedArgs): Promise<number> {
  const input = requirePositional(args, 0, "input path");
  const output = requirePositional(args, 1, "output path");
  if (!args.to) throw new FormatError("seal requires --to <contact>");

  const identity = await loadLocalIdentity(args);
  const contact = store(args).resolve(args.to);
  const result = sealFile({
    sender: identity,
    recipient: contact,
    inputPath: input,
    outputPath: output,
    overwrite: args.overwrite,
    progress: progressHook("sealing"),
  });
  endProgress();
  console.log(`sealed ${result.totalBytes} bytes in ${result.chunkCount} chunks`);
  console.log(`package:     ${result.packagePath}`);
  console.log(`package id:  ${result.packageId.toString("hex")}`);
  console.log(`recipient:   ${contact.name}  ${result.recipientFingerprint}`);
  return 0;
}

async function cmdOpen(args: ParsedArgs): Promise<number> {
  const input = requirePositional(args, 0, "input path");
  const output = requirePositional(args, 1, "output path");
  const identity = await loadLocalIdentity(args);
  const result = openFile({
    recipient: identity,
    contacts: store(args),
    packagePath: input,
    outputPath: output,
    overwrite: args.overwrite,
    progress: progressHook("opening"),
  });
  endProgress();
  console.log(`opened ${result.totalBytes} bytes in ${result.chunkCount} chunks`);
  console.log(`output:      ${result.outputPath}`);
  console.log(`package id:  ${result.packageId.toString("hex")}`);
  console.log(`sender:      ${result.senderName}  ${result.senderFingerprint}`);
  return 0;
}

const COMMANDS: Record<string, (args: ParsedArgs) => Promise<number>> = {
  "generate-identity": cmdGenerateIdentity,
  "export-public-identity": cmdExportPublicIdentity,
  "show-identity": cmdShowIdentity,
  "migrate-legacy-identity": cmdMigrateLegacyIdentity,
  "import-contact": cmdImportContact,
  "verify-contact": cmdVerifyContact,
  "list-contacts": cmdListContacts,
  "revoke-contact": cmdRevokeContact,
  seal: cmdSeal,
  open: cmdOpen,
};

function requirePositional(args: ParsedArgs, index: number, what: string): string {
  const value = args.positional[index];
  if (value === undefined) {
    throw new FormatError(`${args.command} requires a ${what}`);
  }
  return value;
}

// ---- Parsing -------------------------------------------------------------

export const USAGE = `albpkg ${VERSION} -- signed post-quantum file packages

Suite ${SUITE_NAME}: ML-KEM-768, ML-DSA-65, HKDF-SHA-256, AES-256-GCM.
Chunk size ${CHUNK_SIZE} bytes.

Usage:
  albpkg [global options] <command> [arguments]

Commands:
  generate-identity                    create a new identity keypair set
  export-public-identity <out>         write your shareable public identity
  show-identity                        print your own fingerprint
  migrate-legacy-identity <old>        explicitly convert ALBPKSK2 to encrypted PKCS#8
  import-contact <name> <file>         import a contact's public identity
  verify-contact <contact> <fpr>       confirm a full fingerprint out of band
  list-contacts                        list contacts and their trust state
  revoke-contact <contact>             locally revoke a contact
  seal <in> <out> --to <contact>       encrypt and sign for one verified contact
  open <in> <out>                      verify and decrypt a package

Global options:
  --home <dir>          configuration directory
  --identity <file>     private identity file (default: <home>/identity.key)
  --passphrase-fd <n>   read the passphrase from this file descriptor
  --overwrite           allow an existing destination to be replaced
  --version             print the version
  --help                print this message

Passphrases are never read from the command line. Use the interactive prompt,
--passphrase-fd, or ALBPKG_PASSPHRASE_FILE.
`;

export function parseArgs(argv: readonly string[]): ParsedArgs {
  const parsed: ParsedArgs = {
    home: defaultHome(),
    command: "",
    positional: [],
    overwrite: false,
  };

  let index = 0;
  while (index < argv.length) {
    const token = argv[index]!;
    if (token === "--passphrase" || token.startsWith("--passphrase=")) {
      // Deliberately not supported: argv is visible in shell history and to
      // anything that can list process command lines.
      throw new FormatError(
        "--passphrase is not supported; use --passphrase-fd or ALBPKG_PASSPHRASE_FILE",
      );
    }
    if (token === "--home") {
      parsed.home = expectValue(argv, ++index, "--home");
    } else if (token === "--identity") {
      parsed.identity = expectValue(argv, ++index, "--identity");
    } else if (token === "--passphrase-fd") {
      const raw = expectValue(argv, ++index, "--passphrase-fd");
      const fd = Number(raw);
      if (!Number.isSafeInteger(fd) || fd < 0) {
        throw new FormatError("--passphrase-fd must be a non-negative integer");
      }
      parsed.passphraseFd = fd;
    } else if (token === "--to") {
      parsed.to = expectValue(argv, ++index, "--to");
    } else if (token === "--overwrite") {
      parsed.overwrite = true;
    } else if (token === "--help" || token === "-h") {
      parsed.command = "--help";
      return parsed;
    } else if (token === "--version") {
      parsed.command = "--version";
      return parsed;
    } else if (token.startsWith("-")) {
      throw new FormatError(`unknown option ${token}`);
    } else if (parsed.command === "") {
      parsed.command = token;
    } else {
      parsed.positional.push(token);
    }
    index += 1;
  }

  if (parsed.command === "") {
    throw new FormatError("a command is required");
  }
  return parsed;
}

function expectValue(argv: readonly string[], index: number, option: string): string {
  const value = argv[index];
  if (value === undefined) throw new FormatError(`${option} requires a value`);
  return value;
}

export async function main(argv: readonly string[]): Promise<number> {
  let args: ParsedArgs;
  try {
    args = parseArgs(argv);
  } catch (error) {
    reportError(error);
    process.stderr.write(USAGE);
    return 2;
  }

  if (args.command === "--help") {
    process.stdout.write(USAGE);
    return 0;
  }
  if (args.command === "--version") {
    console.log(`albpkg ${VERSION}`);
    return 0;
  }

  const handler = COMMANDS[args.command];
  if (handler === undefined) {
    process.stderr.write(`albpkg: unknown command '${args.command}'\n`);
    process.stderr.write(USAGE);
    return 2;
  }

  try {
    return await handler(args);
  } catch (error) {
    endProgress();
    reportError(error);
    return 2;
  }
}

function reportError(error: unknown): void {
  if (error instanceof AlbpkgError) {
    process.stderr.write(`albpkg: ${error.toString()}\n`);
  } else if (error instanceof Error) {
    process.stderr.write(`albpkg: ${error.message}\n`);
  } else {
    process.stderr.write("albpkg: unknown failure\n");
  }
}

if (import.meta.main) {
  main(process.argv.slice(2))
    .then((code) => {
      process.exitCode = code;
    })
    .catch(() => {
      process.exitCode = 2;
    });
}
