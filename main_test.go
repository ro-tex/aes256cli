package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/blake2b"
)

// newTestAEAD derives an AEAD the same way encodeDecode does, for use
// directly in tests without going through the terminal/file machinery.
func newTestAEAD(t *testing.T, password string) cipher.AEAD {
	t.Helper()
	key := blake2b.Sum256([]byte(password))
	c, err := aes.NewCipher(key[:])
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	aead, err := cipher.NewGCM(c)
	if err != nil {
		t.Fatalf("cipher.NewGCM: %v", err)
	}
	return aead
}

// randomBytes returns n deterministic-per-seed but non-repeating bytes,
// good enough as plaintext fixtures without needing crypto/rand in tests.
func fillBytes(n int, seed byte) []byte {
	b := make([]byte, n)
	x := seed
	for i := range b {
		x = x*31 + 7
		b[i] = x
	}
	return b
}

// ---------------------------------------------------------------------
// chunkNonce
// ---------------------------------------------------------------------

func TestChunkNonce(t *testing.T) {
	base := []byte{0xAA, 0xBB, 0xCC, 0xDD, 1, 2, 3, 4, 5, 6, 7, 8}

	n0 := chunkNonce(base, 0)
	if !bytes.Equal(n0[:4], base[:4]) {
		t.Errorf("counter 0 should leave the high 4 bytes untouched: got %x, want prefix %x", n0, base[:4])
	}
	if !bytes.Equal(n0[4:], base[4:]) {
		t.Errorf("counter 0 should leave the nonce unchanged: got %x, want %x", n0, base)
	}

	seen := map[string]bool{}
	for counter := uint64(0); counter < 10000; counter++ {
		n := chunkNonce(base, counter)
		if len(n) != len(base) {
			t.Fatalf("chunkNonce changed length: got %d, want %d", len(n), len(base))
		}
		if !bytes.Equal(n[:4], base[:4]) {
			t.Fatalf("chunkNonce touched the high bytes at counter %d: got %x", counter, n)
		}
		key := hex.EncodeToString(n)
		if seen[key] {
			t.Fatalf("nonce collision at counter %d: %x", counter, n)
		}
		seen[key] = true
	}

	// Must not mutate the base slice passed in.
	baseCopy := append([]byte{}, base...)
	_ = chunkNonce(base, 12345)
	if !bytes.Equal(base, baseCopy) {
		t.Errorf("chunkNonce mutated its base argument: got %x, want %x", base, baseCopy)
	}

	// Deterministic: same inputs, same output.
	a := chunkNonce(base, 42)
	b := chunkNonce(base, 42)
	if !bytes.Equal(a, b) {
		t.Errorf("chunkNonce is not deterministic: %x vs %x", a, b)
	}
}

// ---------------------------------------------------------------------
// streamEncrypt / streamDecrypt round trips
// ---------------------------------------------------------------------

func roundTrip(t *testing.T, aead cipher.AEAD, baseNonce, plaintext []byte) []byte {
	t.Helper()
	var ciphertext bytes.Buffer
	if err := streamEncrypt(bytes.NewReader(plaintext), &ciphertext, aead, baseNonce); err != nil {
		t.Fatalf("streamEncrypt: %v", err)
	}
	var recovered bytes.Buffer
	if err := streamDecrypt(bytes.NewReader(ciphertext.Bytes()), &recovered, aead, baseNonce); err != nil {
		t.Fatalf("streamDecrypt: %v", err)
	}
	if !bytes.Equal(recovered.Bytes(), plaintext) {
		t.Fatalf("round trip mismatch: got %d bytes, want %d bytes", recovered.Len(), len(plaintext))
	}
	return ciphertext.Bytes()
}

func TestStreamRoundTrip(t *testing.T) {
	aead := newTestAEAD(t, "correct horse battery staple")
	baseNonce := fillBytes(aead.NonceSize(), 1)

	sizes := []int{
		0,
		1,
		ChunkSize - 1,
		ChunkSize,
		ChunkSize + 1,
		2 * ChunkSize,
		3*ChunkSize + 12345,
	}
	for _, size := range sizes {
		t.Run(fmt.Sprintf("size=%d", size), func(t *testing.T) {
			plaintext := fillBytes(size, byte(size))
			ciphertext := roundTrip(t, aead, baseNonce, plaintext)

			wantChunks := size / ChunkSize
			if size == 0 || size%ChunkSize != 0 {
				wantChunks++
			}
			wantLen := size + wantChunks*aead.Overhead()
			if len(ciphertext) != wantLen {
				t.Errorf("ciphertext length = %d, want %d (plaintext %d bytes in %d chunks)", len(ciphertext), wantLen, size, wantChunks)
			}
		})
	}
}

func TestStreamEncryptEmptyFileProducesOneFinalChunk(t *testing.T) {
	aead := newTestAEAD(t, "pw")
	baseNonce := fillBytes(aead.NonceSize(), 2)

	var ciphertext bytes.Buffer
	if err := streamEncrypt(bytes.NewReader(nil), &ciphertext, aead, baseNonce); err != nil {
		t.Fatalf("streamEncrypt: %v", err)
	}
	if got, want := ciphertext.Len(), aead.Overhead(); got != want {
		t.Fatalf("empty-file ciphertext length = %d, want %d (tag only)", got, want)
	}
}

func TestStreamDecryptWrongKey(t *testing.T) {
	aead1 := newTestAEAD(t, "password one")
	aead2 := newTestAEAD(t, "password two")
	baseNonce := fillBytes(aead1.NonceSize(), 3)

	plaintext := fillBytes(3*ChunkSize+500, 9)
	var ciphertext bytes.Buffer
	if err := streamEncrypt(bytes.NewReader(plaintext), &ciphertext, aead1, baseNonce); err != nil {
		t.Fatalf("streamEncrypt: %v", err)
	}

	var out bytes.Buffer
	err := streamDecrypt(bytes.NewReader(ciphertext.Bytes()), &out, aead2, baseNonce)
	if err == nil {
		t.Fatal("expected an error decrypting with the wrong key, got nil")
	}
}

func TestStreamDecryptTamperedByte(t *testing.T) {
	aead := newTestAEAD(t, "pw")
	baseNonce := fillBytes(aead.NonceSize(), 4)

	plaintext := fillBytes(2*ChunkSize+42, 11)
	var ciphertext bytes.Buffer
	if err := streamEncrypt(bytes.NewReader(plaintext), &ciphertext, aead, baseNonce); err != nil {
		t.Fatalf("streamEncrypt: %v", err)
	}

	tampered := append([]byte{}, ciphertext.Bytes()...)
	tampered[len(tampered)/2] ^= 0xFF

	var out bytes.Buffer
	err := streamDecrypt(bytes.NewReader(tampered), &out, aead, baseNonce)
	if err == nil {
		t.Fatal("expected an error decrypting tampered ciphertext, got nil")
	}
}

func TestStreamDecryptTruncated(t *testing.T) {
	aead := newTestAEAD(t, "pw")
	baseNonce := fillBytes(aead.NonceSize(), 5)

	// Single-chunk plaintext: truncating it removes the only (final) chunk,
	// so nothing at all should be written out.
	plaintext := fillBytes(100, 13)
	var ciphertext bytes.Buffer
	if err := streamEncrypt(bytes.NewReader(plaintext), &ciphertext, aead, baseNonce); err != nil {
		t.Fatalf("streamEncrypt: %v", err)
	}
	truncated := ciphertext.Bytes()[:ciphertext.Len()-10]

	var out bytes.Buffer
	err := streamDecrypt(bytes.NewReader(truncated), &out, aead, baseNonce)
	if err == nil {
		t.Fatal("expected an error decrypting truncated ciphertext, got nil")
	}
	if out.Len() != 0 {
		t.Errorf("truncated single-chunk decrypt wrote %d bytes of plaintext, want 0", out.Len())
	}

	// Multi-chunk plaintext: drop the final chunk entirely. The stream now
	// ends right after a chunk that was sealed as "more to come" - decrypt
	// must notice and fail rather than silently accepting a short file.
	big := fillBytes(2*ChunkSize+100, 17)
	var bigCiphertext bytes.Buffer
	if err := streamEncrypt(bytes.NewReader(big), &bigCiphertext, aead, baseNonce); err != nil {
		t.Fatalf("streamEncrypt: %v", err)
	}
	lastChunkSize := 100 + aead.Overhead()
	droppedFinal := bigCiphertext.Bytes()[:bigCiphertext.Len()-lastChunkSize]

	var out2 bytes.Buffer
	err = streamDecrypt(bytes.NewReader(droppedFinal), &out2, aead, baseNonce)
	if err == nil {
		t.Fatal("expected an error when the final chunk is missing, got nil")
	}
}

func TestStreamDecryptAppendedGarbage(t *testing.T) {
	aead := newTestAEAD(t, "pw")
	baseNonce := fillBytes(aead.NonceSize(), 6)

	plaintext := fillBytes(500, 19)
	var ciphertext bytes.Buffer
	if err := streamEncrypt(bytes.NewReader(plaintext), &ciphertext, aead, baseNonce); err != nil {
		t.Fatalf("streamEncrypt: %v", err)
	}
	withGarbage := append(append([]byte{}, ciphertext.Bytes()...), []byte("trailing garbage")...)

	var out bytes.Buffer
	err := streamDecrypt(bytes.NewReader(withGarbage), &out, aead, baseNonce)
	if err == nil {
		t.Fatal("expected an error decrypting ciphertext with appended garbage, got nil")
	}
}

func TestStreamDecryptEmptyCiphertext(t *testing.T) {
	aead := newTestAEAD(t, "pw")
	baseNonce := fillBytes(aead.NonceSize(), 7)

	var out bytes.Buffer
	err := streamDecrypt(bytes.NewReader(nil), &out, aead, baseNonce)
	if err == nil {
		t.Fatal("expected an error decrypting a completely empty ciphertext stream, got nil")
	}
}

// ---------------------------------------------------------------------
// legacyDecrypt (backward compatibility with the pre-chunking format)
// ---------------------------------------------------------------------

func TestLegacyDecryptRoundTrip(t *testing.T) {
	aead := newTestAEAD(t, "legacy pw")
	nonce := fillBytes(aead.NonceSize(), 21)
	plaintext := []byte("some legacy plaintext, sealed the old way")

	sealed := aead.Seal(nil, nonce, plaintext, nil)
	blob := append(append([]byte{}, nonce...), sealed...)

	got, err := legacyDecrypt(blob, aead)
	if err != nil {
		t.Fatalf("legacyDecrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("legacyDecrypt = %q, want %q", got, plaintext)
	}
}

func TestLegacyDecryptTooShort(t *testing.T) {
	aead := newTestAEAD(t, "pw")
	_, err := legacyDecrypt([]byte{1, 2, 3}, aead)
	if err == nil {
		t.Fatal("expected an error for a blob shorter than the nonce, got nil")
	}
}

func TestLegacyDecryptWrongPassword(t *testing.T) {
	aead1 := newTestAEAD(t, "right password")
	aead2 := newTestAEAD(t, "wrong password")
	nonce := fillBytes(aead1.NonceSize(), 22)
	sealed := aead1.Seal(nil, nonce, []byte("secret"), nil)
	blob := append(append([]byte{}, nonce...), sealed...)

	_, err := legacyDecrypt(blob, aead2)
	if err == nil {
		t.Fatal("expected an error decrypting legacy blob with the wrong password, got nil")
	}
}

// TestLegacyDecryptGoldenRegression pins byte-for-byte decoding of a fixed
// ciphertext produced by the original (pre-chunking) implementation's
// scheme: nonce || Seal(nonce, nonce, plaintext, nil). This guards against
// ever accidentally breaking the ability to open files that were encrypted
// before chunking/streaming was introduced.
func TestLegacyDecryptGoldenRegression(t *testing.T) {
	const goldenHex = "000000000000000000000000f50baf89f7291c1ac3af84534ddcc92e4976786d33fc738dba33efc32df5306964ef53c73587dcbaed1fa760aecb4450"
	const wantPlaintext = "legacy format regression fixture"

	blob, err := hex.DecodeString(goldenHex)
	if err != nil {
		t.Fatalf("bad golden hex fixture: %v", err)
	}
	aead := newTestAEAD(t, "regression-test-password")

	got, err := legacyDecrypt(blob, aead)
	if err != nil {
		t.Fatalf("legacyDecrypt on golden fixture: %v", err)
	}
	if string(got) != wantPlaintext {
		t.Fatalf("legacyDecrypt golden = %q, want %q", got, wantPlaintext)
	}
}

// ---------------------------------------------------------------------
// New (chunked) format regression
// ---------------------------------------------------------------------

// TestFormatMagicPinned locks the on-disk format identifier. Legacy-format
// detection during decrypt depends on this value never colliding with a
// plausible random nonce prefix; changing it is a wire-format break.
func TestFormatMagicPinned(t *testing.T) {
	if string(formatMagic) != "AEC2" {
		t.Fatalf("formatMagic = %q, want %q", formatMagic, "AEC2")
	}
	if len(formatMagic) != 4 {
		t.Fatalf("len(formatMagic) = %d, want 4", len(formatMagic))
	}
}

// TestNewFormatGoldenRegression pins the exact bytes the chunked format
// produces for a fixed key, base nonce and plaintext spanning two chunks
// (one full ChunkSize chunk plus a short final one). If ChunkSize, the
// nonce-derivation scheme, the associated-data final-chunk flag, or chunk
// ordering ever changes, this test's hash will no longer match and the
// change has to be made deliberately rather than by accident.
func TestNewFormatGoldenRegression(t *testing.T) {
	const wantSHA256 = "bca29c494920233e8c48113879625217967acbd97d724685388ae0cbb775aea0"

	aead := newTestAEAD(t, "regression-test-password")
	baseNonce := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c}

	plaintext := make([]byte, ChunkSize+777)
	for i := range plaintext {
		plaintext[i] = byte(i % 251)
	}

	var out bytes.Buffer
	out.Write(formatMagic)
	out.Write(baseNonce)
	if err := streamEncrypt(bytes.NewReader(plaintext), &out, aead, baseNonce); err != nil {
		t.Fatalf("streamEncrypt: %v", err)
	}

	sum := sha256.Sum256(out.Bytes())
	if gotHex := hex.EncodeToString(sum[:]); gotHex != wantSHA256 {
		t.Fatalf("golden new-format sha256 = %s, want %s (wire format changed?)", gotHex, wantSHA256)
	}

	// And it must still decrypt back to the exact original plaintext.
	body := out.Bytes()[len(formatMagic)+len(baseNonce):]
	var recovered bytes.Buffer
	if err := streamDecrypt(bytes.NewReader(body), &recovered, aead, baseNonce); err != nil {
		t.Fatalf("streamDecrypt: %v", err)
	}
	if !bytes.Equal(recovered.Bytes(), plaintext) {
		t.Fatal("golden new-format round trip mismatch")
	}
}

// ---------------------------------------------------------------------
// createOutputFile
// ---------------------------------------------------------------------

// withStdin temporarily replaces os.Stdin with the given content for the
// duration of fn, restoring the original afterwards. createOutputFile's
// overwrite prompt uses fmt.Scanln (not a raw terminal read), so a plain
// pipe/file works fine here - no pty needed.
func withStdin(t *testing.T, content string, fn func()) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	orig := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = orig }()

	done := make(chan struct{})
	go func() {
		_, _ = io.WriteString(w, content)
		_ = w.Close()
		close(done)
	}()
	fn()
	<-done
	_ = r.Close()
}

func TestCreateOutputFileNew(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "plain.txt.aes")

	f, name, err := createOutputFile(filepath.Join(dir, "plain.txt"), true)
	if err != nil {
		t.Fatalf("createOutputFile: %v", err)
	}
	defer f.Close()
	if name != target {
		t.Errorf("output name = %q, want %q", name, target)
	}
}

func TestCreateOutputFileDecryptStripsExtension(t *testing.T) {
	dir := t.TempDir()
	_, name, err := createOutputFile(filepath.Join(dir, "secret.txt.aes"), false)
	if err != nil {
		t.Fatalf("createOutputFile: %v", err)
	}
	want := filepath.Join(dir, "secret.txt")
	if name != want {
		t.Errorf("output name = %q, want %q", name, want)
	}
}

func TestCreateOutputFileOverwriteDeclined(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "out.txt")
	if err := os.WriteFile(target, []byte("original"), FilePerm); err != nil {
		t.Fatalf("seed file: %v", err)
	}

	var err error
	withStdin(t, "n\n", func() {
		_, _, err = createOutputFile(target+".aes", false) // decrypt -> strips to "out.txt", which exists
	})
	if err == nil {
		t.Fatal("expected an error when declining to overwrite, got nil")
	}
	got, rerr := os.ReadFile(target)
	if rerr != nil {
		t.Fatalf("ReadFile: %v", rerr)
	}
	if string(got) != "original" {
		t.Errorf("declined overwrite modified the file: got %q", got)
	}
}

// TestCreateOutputFileOverwriteTruncates is a regression test for a bug
// where the output file was opened without O_TRUNC: overwriting an
// existing, longer file with shorter new content left the old file's
// trailing bytes in place, corrupting the result.
func TestCreateOutputFileOverwriteTruncates(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "out.txt")
	longContent := bytes.Repeat([]byte("x"), 1000)
	if err := os.WriteFile(target, longContent, FilePerm); err != nil {
		t.Fatalf("seed file: %v", err)
	}

	var f *os.File
	var err error
	withStdin(t, "y\n", func() {
		f, _, err = createOutputFile(target+".aes", false) // decrypt -> strips to "out.txt", which exists
	})
	if err != nil {
		t.Fatalf("createOutputFile: %v", err)
	}
	shortContent := []byte("short")
	if _, err := f.Write(shortContent); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Equal(got, shortContent) {
		t.Fatalf("overwritten file = %q (len %d), want %q (len %d) - stale trailing bytes from the old, longer file were not truncated",
			got, len(got), shortContent, len(shortContent))
	}
}

// ---------------------------------------------------------------------
// readPasswordFromTerminal
// ---------------------------------------------------------------------

func TestReadPasswordFromTerminalRejectsNonTerminal(t *testing.T) {
	// A regular file is never a terminal, unlike the test runner's own
	// stdin (which may or may not be one depending on how `go test` was
	// invoked) - so this is deterministic in CI and locally alike.
	f, err := os.CreateTemp(t.TempDir(), "not-a-tty")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	defer f.Close()

	orig := os.Stdin
	os.Stdin = f
	defer func() { os.Stdin = orig }()

	_, err = readPasswordFromTerminal()
	if err == nil {
		t.Fatal("expected an error reading a password from a non-terminal stdin, got nil")
	}
}

// ---------------------------------------------------------------------
// Full CLI regression tests (black box, via the built binary)
// ---------------------------------------------------------------------

var cliBinPath string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "aes256cli-test-bin")
	if err != nil {
		fmt.Println("failed to create temp dir for test binary:", err)
		os.Exit(1)
	}
	defer os.RemoveAll(dir)

	cliBinPath = filepath.Join(dir, "aes256cli-under-test")
	cmd := exec.Command("go", "build", "-o", cliBinPath, ".")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Println("failed to build CLI binary for regression tests:", err)
		os.Exit(1)
	}

	os.Exit(m.Run())
}

// These exercise flag-validation paths only, which exit before ever trying
// to read a password - so they need no terminal/pty and are safe to run
// under `go test` in any environment (including headless CI).

func TestCLINoArgs(t *testing.T) {
	cmd := exec.Command(cliBinPath, "-e")
	out, err := cmd.CombinedOutput()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 {
		t.Fatalf("expected exit code 1, got err=%v output=%s", err, out)
	}
	if !bytes.Contains(out, []byte("No filename given.")) {
		t.Errorf("output = %q, want it to contain %q", out, "No filename given.")
	}
}

func TestCLIBothEncryptAndDecrypt(t *testing.T) {
	cmd := exec.Command(cliBinPath, "-e", "-d", "somefile")
	out, err := cmd.CombinedOutput()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 {
		t.Fatalf("expected exit code 1, got err=%v output=%s", err, out)
	}
	if !bytes.Contains(out, []byte("must choose to either encrypt")) {
		t.Errorf("output = %q, want it to mention choosing encrypt or decrypt", out)
	}
}

func TestCLINeitherEncryptNorDecrypt(t *testing.T) {
	cmd := exec.Command(cliBinPath, "somefile")
	out, err := cmd.CombinedOutput()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 {
		t.Fatalf("expected exit code 1, got err=%v output=%s", err, out)
	}
	if !bytes.Contains(out, []byte("must choose to either encrypt")) {
		t.Errorf("output = %q, want it to mention choosing encrypt or decrypt", out)
	}
}

func TestCLIMissingInputFile(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "does-not-exist.txt")
	cmd := exec.Command(cliBinPath, "-e", missing)
	out, err := cmd.CombinedOutput()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 {
		t.Fatalf("expected exit code 1, got err=%v output=%s", err, out)
	}
	if !bytes.Contains(out, []byte("Failed to read file")) {
		t.Errorf("output = %q, want it to mention the file could not be read", out)
	}
}
