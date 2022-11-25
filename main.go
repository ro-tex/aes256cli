package main

import (
	"crypto/aes"
	"crypto/cipher"
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
	outFile, err := os.OpenFile(outFileName, os.O_CREATE|os.O_WRONLY, FilePerm)
	if err != nil {
		return nil, "", fmt.Errorf("Failed to open output file %s for writing! Error: %v\n", outFileName, err)
	}
	return outFile, outFileName, nil
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

	// Read the input file in memory. Yes, this is not great.
	inBytes, err := io.ReadAll(inFile)
	if err != nil {
		return err
	}

	// Encrypt or decrypt.
	var outBytes []byte
	if actionEncrypt {
		nonce := make([]byte, aead.NonceSize())
		outBytes = aead.Seal(nonce, nonce, inBytes, nil)
		inBytes = nil
	} else {
		nonceSize := aead.NonceSize()
		if len(inBytes) < nonceSize {
			return errors.New("Unexpected end of ciphertext.")
		}
		nonce, ciphertext := inBytes[:nonceSize], inBytes[nonceSize:]
		inBytes = nil
		outBytes, err = aead.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			return err
		}
	}
	// Write the output to disk.
	_, err = outFile.Write(outBytes)
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
		fmt.Println("You must choose to either encrypt (-e/--encrypt) or decrypt (-d/--decrypt) a file.\n")
		flag.Usage()
		os.Exit(1)
	}

	if flag.NArg() == 0 {
		fmt.Println("No filename given.\n")
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
