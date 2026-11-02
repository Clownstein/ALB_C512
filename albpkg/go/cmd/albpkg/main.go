// Command albpkg is the Go port's command line interface.
//
// Passphrases are never accepted as arguments. They come from a no-echo
// prompt, or -- for automation -- from a file descriptor or a file named by
// ALBPKG_PASSPHRASE_FILE, never from argv and never from a log line.
package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/alb/albpkg/albpkg"
	"golang.org/x/term"
)

const version = "1.0.0"

const usage = `albpkg ` + version + ` -- signed post-quantum file packages

Suite ` + albpkg.SuiteName + `: ML-KEM-768, ML-DSA-65, HKDF-SHA-256, AES-256-GCM.
Chunk size 1048576 bytes.

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
`

type options struct {
	home         string
	identity     string
	passphraseFd int
	overwrite    bool
	to           string
	command      string
	positional   []string
}

func main() {
	code, err := run(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "albpkg: %v\n", err)
	}
	os.Exit(code)
}

func run(argv []string) (int, error) {
	opts, err := parseArgs(argv)
	if err != nil {
		fmt.Fprint(os.Stderr, usage)
		return 2, err
	}

	switch opts.command {
	case "--help":
		fmt.Print(usage)
		return 0, nil
	case "--version":
		fmt.Printf("albpkg %s\n", version)
		return 0, nil
	}

	handler, ok := commands[opts.command]
	if !ok {
		fmt.Fprintf(os.Stderr, "albpkg: unknown command '%s'\n", opts.command)
		fmt.Fprint(os.Stderr, usage)
		return 2, nil
	}
	if err := handler(opts); err != nil {
		return 2, err
	}
	return 0, nil
}

func defaultHome() string {
	if home := os.Getenv("ALBPKG_HOME"); home != "" {
		return home
	}
	dir, err := os.UserHomeDir()
	if err != nil {
		return ".albpkg"
	}
	return filepath.Join(dir, ".albpkg")
}

func parseArgs(argv []string) (*options, error) {
	opts := &options{home: defaultHome(), passphraseFd: -1}

	for i := 0; i < len(argv); i++ {
		token := argv[i]
		switch {
		case token == "--passphrase" || strings.HasPrefix(token, "--passphrase="):
			// Deliberately not supported: argv is visible in shell history and
			// to anything that can list process command lines.
			return nil, errors.New(
				"--passphrase is not supported; use --passphrase-fd or ALBPKG_PASSPHRASE_FILE")
		case token == "--home":
			value, err := expectValue(argv, &i, "--home")
			if err != nil {
				return nil, err
			}
			opts.home = value
		case token == "--identity":
			value, err := expectValue(argv, &i, "--identity")
			if err != nil {
				return nil, err
			}
			opts.identity = value
		case token == "--passphrase-fd":
			value, err := expectValue(argv, &i, "--passphrase-fd")
			if err != nil {
				return nil, err
			}
			fd, err := strconv.Atoi(value)
			if err != nil || fd < 0 {
				return nil, errors.New("--passphrase-fd must be a non-negative integer")
			}
			opts.passphraseFd = fd
		case token == "--to":
			value, err := expectValue(argv, &i, "--to")
			if err != nil {
				return nil, err
			}
			opts.to = value
		case token == "--overwrite":
			opts.overwrite = true
		case token == "--help" || token == "-h":
			opts.command = "--help"
			return opts, nil
		case token == "--version":
			opts.command = "--version"
			return opts, nil
		case strings.HasPrefix(token, "-"):
			return nil, fmt.Errorf("unknown option %s", token)
		case opts.command == "":
			opts.command = token
		default:
			opts.positional = append(opts.positional, token)
		}
	}

	if opts.command == "" {
		return nil, errors.New("a command is required")
	}
	return opts, nil
}

func expectValue(argv []string, i *int, option string) (string, error) {
	*i++
	if *i >= len(argv) {
		return "", fmt.Errorf("%s requires a value", option)
	}
	return argv[*i], nil
}

// ---- Passphrase sourcing -------------------------------------------------

func passphraseProvider(opts *options) albpkg.PassphraseProvider {
	if opts.passphraseFd >= 0 {
		fd := opts.passphraseFd
		return func(string) (string, error) {
			file := os.NewFile(uintptr(fd), "passphrase")
			if file == nil {
				return "", fmt.Errorf("cannot read passphrase from fd %d", fd)
			}
			scanner := bufio.NewScanner(file)
			if !scanner.Scan() {
				return "", fmt.Errorf("cannot read passphrase from fd %d", fd)
			}
			return scanner.Text(), nil
		}
	}

	if path := os.Getenv("ALBPKG_PASSPHRASE_FILE"); path != "" {
		return func(string) (string, error) {
			raw, err := os.ReadFile(path)
			if err != nil {
				return "", errors.New(
					"cannot read the passphrase file named by ALBPKG_PASSPHRASE_FILE")
			}
			text := strings.SplitN(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n", 2)[0]
			return text, nil
		}
	}

	// Interactive no-echo prompt.
	return func(prompt string) (string, error) {
		fd := int(os.Stdin.Fd())
		if !term.IsTerminal(fd) {
			return "", errors.New("no interactive terminal available for a passphrase")
		}
		fmt.Fprintf(os.Stderr, "%s: ", prompt)
		raw, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", errors.New("could not read the passphrase")
		}
		return string(raw), nil
	}
}

func identityPath(opts *options) string {
	if opts.identity != "" {
		return opts.identity
	}
	return filepath.Join(opts.home, "identity.key")
}

func openStore(opts *options) (*albpkg.ContactStore, error) {
	return albpkg.NewContactStore(filepath.Join(opts.home, "contacts"))
}

func loadIdentity(opts *options) (*albpkg.Identity, error) {
	return albpkg.LoadIdentity(identityPath(opts), passphraseProvider(opts))
}

func requirePositional(opts *options, index int, what string) (string, error) {
	if index >= len(opts.positional) {
		return "", fmt.Errorf("%s requires a %s", opts.command, what)
	}
	return opts.positional[index], nil
}

// ---- Commands ------------------------------------------------------------

var commands = map[string]func(*options) error{
	"generate-identity":       cmdGenerateIdentity,
	"export-public-identity":  cmdExportPublicIdentity,
	"show-identity":           cmdShowIdentity,
	"migrate-legacy-identity": cmdMigrateLegacyIdentity,
	"import-contact":          cmdImportContact,
	"verify-contact":          cmdVerifyContact,
	"list-contacts":           cmdListContacts,
	"revoke-contact":          cmdRevokeContact,
	"seal":                    cmdSeal,
	"open":                    cmdOpen,
}

func cmdGenerateIdentity(opts *options) error {
	path := identityPath(opts)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	identity, err := albpkg.GenerateIdentity()
	if err != nil {
		return err
	}
	defer identity.Close()

	if err := albpkg.SaveIdentity(identity, path, passphraseProvider(opts),
		opts.overwrite, 0); err != nil {
		return err
	}
	fmt.Printf("identity written to %s\n", path)
	fmt.Printf("suite:       %s\n", albpkg.SuiteName)
	fmt.Printf("fingerprint: %s\n", identity.Public().FingerprintText())
	fmt.Print("\nGive the full fingerprint to your contacts over a channel you " +
		"already trust.\nThey must compare all 64 characters before they can use " +
		"your key.\n")
	return nil
}

func cmdExportPublicIdentity(opts *options) error {
	target, err := requirePositional(opts, 0, "output path")
	if err != nil {
		return err
	}
	identity, err := loadIdentity(opts)
	if err != nil {
		return err
	}
	defer identity.Close()

	fpr, err := albpkg.ExportPublicIdentity(identity.Public(), target, opts.overwrite)
	if err != nil {
		return err
	}
	fmt.Printf("public identity written to %s\n", target)
	fmt.Printf("fingerprint: %s\n", fpr)
	return nil
}

func cmdShowIdentity(opts *options) error {
	identity, err := loadIdentity(opts)
	if err != nil {
		return err
	}
	defer identity.Close()
	fmt.Printf("suite:       %s\n", albpkg.SuiteName)
	fmt.Printf("fingerprint: %s\n", identity.Public().FingerprintText())
	return nil
}

func cmdMigrateLegacyIdentity(opts *options) error {
	source, err := requirePositional(opts, 0, "legacy identity path")
	if err != nil {
		return err
	}
	target := identityPath(opts)
	identity, err := albpkg.MigrateLegacyIdentity(source, target, passphraseProvider(opts), opts.overwrite)
	if err != nil {
		return err
	}
	defer identity.Close()
	fmt.Printf("migrated identity written to %s\n", target)
	fmt.Printf("original retained at %s\n", source)
	fmt.Printf("fingerprint: %s\n", identity.Public().FingerprintText())
	return nil
}

func cmdImportContact(opts *options) error {
	name, err := requirePositional(opts, 0, "contact name")
	if err != nil {
		return err
	}
	file, err := requirePositional(opts, 1, "public identity file")
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		return fmt.Errorf("cannot read %s", filepath.Base(file))
	}
	public, err := albpkg.PublicIdentityFromArmored(string(raw))
	if err != nil {
		return err
	}
	store, err := openStore(opts)
	if err != nil {
		return err
	}
	contact, err := store.ImportContact(name, public)
	if err != nil {
		return err
	}
	fmt.Printf("imported '%s' as %s\n", contact.Name, contact.Trust)
	fmt.Printf("fingerprint: %s\n", contact.FingerprintText())
	fmt.Printf("\nThis contact is UNVERIFIED and cannot be used yet.\n"+
		"Confirm the fingerprint above with them over a separate, trusted channel,\n"+
		"then run:  albpkg verify-contact %s <fingerprint>\n", contact.Name)
	return nil
}

func cmdVerifyContact(opts *options) error {
	selector, err := requirePositional(opts, 0, "contact")
	if err != nil {
		return err
	}
	fingerprint, err := requirePositional(opts, 1, "fingerprint")
	if err != nil {
		return err
	}
	store, err := openStore(opts)
	if err != nil {
		return err
	}
	contact, err := store.VerifyContact(selector, fingerprint)
	if err != nil {
		return err
	}
	fmt.Printf("'%s' is now verified\n", contact.Name)
	fmt.Printf("fingerprint: %s\n", contact.FingerprintText())
	return nil
}

func cmdListContacts(opts *options) error {
	store, err := openStore(opts)
	if err != nil {
		return err
	}
	contacts, err := store.List()
	if err != nil {
		return err
	}
	if len(contacts) == 0 {
		fmt.Println("no contacts")
		return nil
	}
	width := 0
	for _, contact := range contacts {
		if len(contact.Name) > width {
			width = len(contact.Name)
		}
	}
	for _, contact := range contacts {
		fmt.Printf("%-*s  %-10s  %s\n", width, contact.Name, contact.Trust,
			contact.FingerprintText())
	}
	return nil
}

func cmdRevokeContact(opts *options) error {
	selector, err := requirePositional(opts, 0, "contact")
	if err != nil {
		return err
	}
	store, err := openStore(opts)
	if err != nil {
		return err
	}
	contact, err := store.Revoke(selector)
	if err != nil {
		return err
	}
	fmt.Printf("'%s' is revoked and will be rejected from now on\n", contact.Name)
	return nil
}

func progressHook(label string) albpkg.ProgressHook {
	if !term.IsTerminal(int(os.Stderr.Fd())) {
		return nil
	}
	var last int64
	return func(done, chunks int64) error {
		if chunks-last >= 16 || chunks <= 1 {
			last = chunks
			fmt.Fprintf(os.Stderr, "\r%s: %.1f MiB (%d chunks)",
				label, float64(done)/float64(1<<20), chunks)
		}
		return nil
	}
}

func endProgress() {
	if term.IsTerminal(int(os.Stderr.Fd())) {
		fmt.Fprintln(os.Stderr)
	}
}

func cmdSeal(opts *options) error {
	input, err := requirePositional(opts, 0, "input path")
	if err != nil {
		return err
	}
	output, err := requirePositional(opts, 1, "output path")
	if err != nil {
		return err
	}
	if opts.to == "" {
		return errors.New("seal requires --to <contact>")
	}

	identity, err := loadIdentity(opts)
	if err != nil {
		return err
	}
	defer identity.Close()

	store, err := openStore(opts)
	if err != nil {
		return err
	}
	contact, err := store.Resolve(opts.to)
	if err != nil {
		return err
	}

	result, err := albpkg.SealFile(albpkg.SealOptions{
		Sender:     identity,
		Recipient:  contact,
		InputPath:  input,
		OutputPath: output,
		Overwrite:  opts.overwrite,
		Progress:   progressHook("sealing"),
	})
	endProgress()
	if err != nil {
		return err
	}

	fmt.Printf("sealed %d bytes in %d chunks\n", result.TotalBytes, result.ChunkCount)
	fmt.Printf("package:     %s\n", result.PackagePath)
	fmt.Printf("package id:  %x\n", result.PackageID)
	fmt.Printf("recipient:   %s  %s\n", contact.Name, result.RecipientFingerprint)
	return nil
}

func cmdOpen(opts *options) error {
	input, err := requirePositional(opts, 0, "input path")
	if err != nil {
		return err
	}
	output, err := requirePositional(opts, 1, "output path")
	if err != nil {
		return err
	}
	identity, err := loadIdentity(opts)
	if err != nil {
		return err
	}
	defer identity.Close()

	store, err := openStore(opts)
	if err != nil {
		return err
	}

	result, err := albpkg.OpenFile(albpkg.OpenOptions{
		Recipient:  identity,
		Contacts:   store,
		InputPath:  input,
		OutputPath: output,
		Overwrite:  opts.overwrite,
		Progress:   progressHook("opening"),
	})
	endProgress()
	if err != nil {
		return err
	}

	fmt.Printf("opened %d bytes in %d chunks\n", result.TotalBytes, result.ChunkCount)
	fmt.Printf("output:      %s\n", result.OutputPath)
	fmt.Printf("package id:  %x\n", result.PackageID)
	fmt.Printf("sender:      %s  %s\n", result.SenderName, result.SenderFingerprint)
	return nil
}
