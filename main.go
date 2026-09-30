package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/term"
)

const (
	BinName       = "aes256cli"
	FileExtension = ".aes"
	FilePerm      = 0600

	// ChunkSize is the amount of plaintext (in bytes) sealed per chunk when
	// streaming. Keeping it fixed-size lets us stream arbitrarily large files
	// while only ever holding one chunk in memory. 64KiB matches what other
	// chunked-AEAD formats (e.g. age) use.
	ChunkSize = 64 * 1024
)

// formatMagic prefixes files written by the current (streaming/chunked)
// format, right before the base nonce. Files written by the original,
// non-chunked implementation start directly with a random 12-byte nonce, so
// on decrypt we can tell the two formats apart by checking for this magic.
// A legacy file matching it by chance is a ~1-in-4-billion coincidence.
var formatMagic = []byte("AEC2")

// adContinue/adFinal are used as GCM associated data on each chunk to mark
// whether more chunks follow. Because the associated data is authenticated,
// an attacker cannot truncate the ciphertext stream without the last chunk
// they leave in place failing to decrypt (it will have been sealed with
// adContinue, but the decryptor - having reached the real end of the file -
// will expect adFinal).
var (
	adContinue = []byte{0x00}
	adFinal    = []byte{0x01}
)

// readPasswordFromTerminal prompts the user to enter a password and then reads
// it from stdin.
func readPasswordFromTerminal() (passwd []byte, err error) {
	for len(passwd) == 0 {
		termId := int(os.Stdin.Fd())
		if !term.IsTerminal(termId) {
			return nil, errors.New("Cannot read from terminal! This is required for entering a password. Exiting.")
		}
		fmt.Printf("Enter password: ")
		passwd, err = term.ReadPassword(termId)
		fmt.Println() // ReadPassword eats the newline :(
		if err != nil {
			return nil, err
		}
		if len(passwd) == 0 {
			fmt.Println("Please enter a non-empty password.")
		}
	}
	return passwd, nil
}

// createOutputFile determines the name of the required output file and creates
// it. It does *NOT* close it - that is a responsibility of the caller.
func createOutputFile(inFileName string, actionEncrypt bool) (*os.File, string, error) {
	var outFileName string
	if actionEncrypt {
		outFileName = inFileName + FileExtension
	} else {
		outFileName = strings.TrimSuffix(inFileName, FileExtension)
	}
	// Check if the output file already exists and (if so) whether the user
	// wants to overwrite it or not.
	if _, err := os.Stat(outFileName); err == nil {
		for {
			fmt.Printf("Output file %s already exists.\nDo you want to overwrite it? (y/n) ", outFileName)
			var answer string
			_, err = fmt.Scanln(&answer)
			if err != nil {
				return nil, "", fmt.Errorf("Failed to read answer! Error: %v\n", err)
			}
			answer = strings.Trim(answer, " ")
			if strings.EqualFold(answer, "n") || strings.EqualFold(answer, "no") {
				return nil, "", errors.New("User has chosen not to overwrite. Exiting.")
			}
			if strings.EqualFold(answer, "y") || strings.EqualFold(answer, "yes") {
				break
			}
		}
	}
	outFile, err := os.OpenFile(outFileName, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, FilePerm)
	if err != nil {
		return nil, "", fmt.Errorf("Failed to open output file %s for writing! Error: %v\n", outFileName, err)
	}
	return outFile, outFileName, nil
}

// chunkNonce derives the per-chunk nonce from the file's random base nonce
// and a monotonically increasing chunk counter, by XORing the counter (as
// big-endian) into the low 8 bytes of the base nonce. Every chunk in a file
// therefore gets a distinct nonce (the counter never repeats within a
// file), while the untouched high bytes of the base nonce keep the
// birthday-bound collision resistance across different files/passwords that
// the original per-file random nonce provided.
func chunkNonce(base []byte, counter uint64) []byte {
	nonce := make([]byte, len(base))
	copy(nonce, base)
	var ctrBytes [8]byte
	binary.BigEndian.PutUint64(ctrBytes[:], counter)
	offset := len(nonce) - len(ctrBytes)
	for i, b := range ctrBytes {
		nonce[offset+i] ^= b
	}
	return nonce
}

// streamEncrypt reads plaintext from r in fixed-size chunks and writes each
// sealed chunk to w, so the whole file never has to be held in memory. The
// last chunk (which may be empty, e.g. for a 0-byte input file) is sealed
// with adFinal so the decryptor can detect a truncated ciphertext stream.
func streamEncrypt(r io.Reader, w io.Writer, aead cipher.AEAD, baseNonce []byte) error {
	in := bufio.NewReaderSize(r, ChunkSize+1)
	out := bufio.NewWriter(w)

	buf := make([]byte, ChunkSize)
	for counter := uint64(0); ; counter++ {
		n, err := io.ReadFull(in, buf)
		if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
			return err
		}
		// Peek to see whether any plaintext remains beyond this chunk.
		_, peekErr := in.Peek(1)
		isFinal := peekErr != nil

		ad := adContinue
		if isFinal {
			ad = adFinal
		}
		ciphertext := aead.Seal(nil, chunkNonce(baseNonce, counter), buf[:n], ad)
		if _, err := out.Write(ciphertext); err != nil {
			return err
		}
		if isFinal {
			break
		}
	}
	return out.Flush()
}

// streamDecrypt is the inverse of streamEncrypt: it reads sealed chunks
// from r, verifies and decrypts each one, and writes the recovered
// plaintext to w. It rejects a ciphertext stream that ends before a chunk
// marked final was seen (truncation) as well as one with extra trailing
// bytes after the final chunk.
func streamDecrypt(r io.Reader, w io.Writer, aead cipher.AEAD, baseNonce []byte) error {
	overhead := aead.Overhead()
	chunkCipherSize := ChunkSize + overhead

	in := bufio.NewReaderSize(r, chunkCipherSize+1)
	out := bufio.NewWriter(w)

	buf := make([]byte, chunkCipherSize)
	for counter := uint64(0); ; counter++ {
		n, err := io.ReadFull(in, buf)
		if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
			return err
		}
		if n < overhead {
			return errors.New("Unexpected end of ciphertext.")
		}
		// Peek to see whether any ciphertext remains beyond this chunk.
		_, peekErr := in.Peek(1)
		isFinal := peekErr != nil

		ad := adContinue
		if isFinal {
			ad = adFinal
		}
		plaintext, err := aead.Open(nil, chunkNonce(baseNonce, counter), buf[:n], ad)
		if err != nil {
			return errors.New("Decryption failed: wrong password, or file is corrupted/truncated/tampered with.")
		}
		if _, err := out.Write(plaintext); err != nil {
			return err
		}
		if isFinal {
			break
		}
	}
	return out.Flush()
}

// legacyDecrypt decrypts data written by the original, non-chunked
// implementation: a single nonce followed by the entire plaintext sealed as
// one GCM message. Kept for backward compatibility with files that predate
// the chunked/streaming format. Because that format authenticates the whole
// file as one atomic blob, it has to be fully buffered - there is no way to
// verify or decrypt it incrementally.
func legacyDecrypt(ciphertext []byte, aead cipher.AEAD) ([]byte, error) {
	nonceSize := aead.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("Unexpected end of ciphertext.")
	}
	nonce, sealed := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return aead.Open(nil, nonce, sealed, nil)
}

// encodeDecode handles encryption and decryption.
func encodeDecode(filename string, actionEncrypt bool) error {
	inFile, err := os.Open(filename)
	if err != nil {
		fmt.Printf("Failed to read file %s! Error: %v\n", filename, err)
		os.Exit(1)
	}
	defer func() { _ = inFile.Close() }()

	outFile, outFName, err := createOutputFile(filename, actionEncrypt)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	// Make sure we close the output file and clean up in case of failure.
	success := false
	defer func() {
		_ = outFile.Close()
		if !success {
			err := os.Remove(outFName)
			if err != nil {
				fmt.Printf("Failed to clean up output file! Error: %v\n", err)
			}
		}
	}()

	// Get the password and convert it to an encryption key and a mac key.
	pass, err := readPasswordFromTerminal()
	if err != nil {
		return err
	}
	// Hash it, so it's padded to exactly 32 bytes.
	key := blake2b.Sum256(pass)
	c, err := aes.NewCipher(key[:])
	if err != nil {
		return err
	}
	// Galois/Counter Mode - https://en.wikipedia.org/wiki/Galois/Counter_Mode
	aead, err := cipher.NewGCM(c)
	if err != nil {
		fmt.Println(err)
	}

	if actionEncrypt {
		baseNonce := make([]byte, aead.NonceSize())
		if _, err := rand.Read(baseNonce); err != nil {
			return err
		}
		if _, err := outFile.Write(formatMagic); err != nil {
			return err
		}
		if _, err := outFile.Write(baseNonce); err != nil {
			return err
		}
		err = streamEncrypt(inFile, outFile, aead, baseNonce)
	} else {
		// Peek at the first few bytes to tell current-format (chunked, magic
		// prefixed) files apart from files written by the original
		// non-chunked implementation, which start directly with a random
		// nonce and carry no magic.
		in := bufio.NewReader(inFile)
		magicBuf := make([]byte, len(formatMagic))
		magicN, magicErr := io.ReadFull(in, magicBuf)

		if magicErr == nil && bytes.Equal(magicBuf, formatMagic) {
			baseNonce := make([]byte, aead.NonceSize())
			if _, err := io.ReadFull(in, baseNonce); err != nil {
				return errors.New("Unexpected end of ciphertext.")
			}
			err = streamDecrypt(in, outFile, aead, baseNonce)
		} else {
			rest, rerr := io.ReadAll(in)
			if rerr != nil {
				return rerr
			}
			inBytes := append(magicBuf[:magicN], rest...)
			var outBytes []byte
			outBytes, err = legacyDecrypt(inBytes, aead)
			if err == nil {
				_, err = outFile.Write(outBytes)
			}
		}
	}
	// If there is no error, then the operation was successful, and we should
	// not remove the output file.
	success = err == nil
	return err
}

func main() {
	flag.Usage = func() {
		_, _ = fmt.Fprintf(flag.CommandLine.Output(), "Usage of %s:\n\n", BinName)
		_, _ = fmt.Fprintf(flag.CommandLine.Output(), "%s [operation] FILENAME\n\n", BinName)
		flag.PrintDefaults()
	}
	actionEncrypt := flag.Bool("encrypt", false, "encrypt a file")
	flag.BoolVar(actionEncrypt, "e", false, "encrypt a file")
	actionDecrypt := flag.Bool("decrypt", false, "decrypt a file")
	flag.BoolVar(actionDecrypt, "d", false, "decrypt a file")
	flag.Parse()

	if (!*actionEncrypt && !*actionDecrypt) || (*actionEncrypt && *actionDecrypt) {
		fmt.Println("You must choose to either encrypt (-e/--encrypt) or decrypt (-d/--decrypt) a file.")
		flag.Usage()
		os.Exit(1)
	}

	if flag.NArg() == 0 {
		fmt.Println("No filename given.")
		flag.Usage()
		os.Exit(1)
	}
	inFName := flag.Arg(0)

	err := encodeDecode(inFName, *actionEncrypt)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
