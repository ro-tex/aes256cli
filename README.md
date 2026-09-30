# aes256cli

A simple file encrypt/decrypt tool.

The tool uses [Go](https://go.dev/)'s built-in [crypto/aes](https://pkg.go.dev/crypto/aes) library to encrypt the input
file with [AES-256](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard).

## Installation

If you have [Go](https://go.dev/) installed:

```shell
go install github.com/ro-tex/aes256cli@latest
```

## Usage

To encrypt a file:

```shell
aes256cli -e myFile.dat
```

To decrypt a file:

```shell
aes256cli -d myFile.dat.aes
```

To print the version and the git commit the binary was built from:

```shell
$ aes256cli -v
aes256cli v0.1.0 (commit 508e3d9)
```

To see the usage information run the tool without parameters:

```shell
$ aes256cli 
You must choose to either encrypt (-e/--encrypt) or decrypt (-d/--decrypt) a file.

Usage of aes256cli:

aes256cli [operation] FILENAME

  -d    decrypt a file
  -decrypt
        decrypt a file
  -e    encrypt a file
  -encrypt
        encrypt a file
  -v    print version and commit hash
  -version
        print version and commit hash
```

## Building

The version and commit hash are injected at build time via `ldflags`:

```shell
go build -ldflags "-X main.version=v0.1.0 -X main.commit=$(git rev-parse HEAD)" .
```

Without these flags, the binary reports version `dev` and commit `none`.

Only the first 7 characters of the commit hash are printed, so passing either the full or the short hash works.
