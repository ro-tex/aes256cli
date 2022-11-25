# aes256cli

A simple file encrypt/decrypt tool.

The tool uses [Go](https://go.dev/)'s built-in [crypto/aes](https://pkg.go.dev/crypto/aes) library to encrypt the input
file with [AES-256](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard).

### Caveat

Currently, the `aes256cli` reads the entire input file in memory before encrypting it and writing it to disk. This means
that you can easily run out of memory if you try encrypting a large file. I hope to address this in the near future.

## Installation

If you have [Go](https://go.dev/) installed:

```shell
go install github.com/ro-tex/aes256cli@latest
```

If you prefer a binary, you can download a Linux amd64 one from https://github.com/ro-tex/aes256cli/releases.

## Usage

To encrypt a file:

```shell
aes256cli -e myFile.dat
```

To decrypt a file:

```shell
aes256cli -d myFile.dat.aes
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
```
