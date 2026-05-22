package crypto

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/klauspost/compress/zstd"
)

// Options defines settings for the protection process.
type Options struct {
	Passphrase      SecretBytes
	PublicKey       []byte      // Deprecated: use Recipients
	Recipients      [][]byte    // Supports multi-recipient encryption
	LocalPrivateKey SecretBytes // Local KEM private key for decryption
	SigningKey      SecretBytes // ML-DSA private key for integrated signing
	ProfileID       *byte       // nil for default
	Compress        *bool
	IsArchive       bool
	Concurrency     *int               // nil for auto
	TotalSize       int64              // Known total size of input for progress tracking
	EventStream     chan<- EngineEvent // Optional channel for telemetry
	ProgressReader  io.Reader          // Deprecated: use EventStream
	Verbose         *bool              // Enables internal slog tracing
	Stealth         *bool              // Enables fingerprint resistance (headerless)
	TraceID         string             // Correlation ID for distributed observability
	SessionKey      SecretBytes        // Pre-derived 32-byte key; when set, KDF is skipped
	SessionSalt     []byte             // Salt used to derive SessionKey (stored in header for self-description)

	// FormatVersion controls the .makn wire format used for new encryptions.
	// 0 = default (V2: MAK2/MAK3 with TLV extensions, HeaderMAC, terminator)
	// 1 = legacy V1 (MAKN/MAKA) — use only when the receiver cannot upgrade
	// 2 = V2 explicit (same as 0)
	// The decrypt path always auto-detects the format regardless of this field.
	FormatVersion byte
}

func (o *Options) Emit(ev EngineEvent) {
	if o.EventStream != nil {
		defer func() { _ = recover() }()
		o.EventStream <- ev
	}
}

// Protect handles the full encryption pipeline under the active policy.
func (e *Engine) ProtectStream(ectx *EngineContext, inputName string, r io.Reader, w io.Writer, opts Options) (EncryptResult, error) {
	ectx = e.context(ectx)
	traceID := opts.TraceID
	if traceID == "" {
		traceID = GenerateTraceID()
	}
	ectx.TraceID = traceID
	log := e.Logger.With("trace_id", traceID, "action", "protect", "input", inputName)

	if opts.EventStream != nil && ectx.Events == nil {
		ectx.Events = opts.EventStream
	}

	if inputName != "-" && inputName != "" {
		if err := ectx.Policy.ValidatePath(inputName); err != nil {
			log.Error("path validation failed", "err", err)
			return EncryptResult{}, err
		}
	}

	// Merge options with configuration defaults.
	profileWasNil := opts.ProfileID == nil
	e.resolvePipelineOptions(ectx, &opts)
	if profileWasNil {
		log.Debug("using default profile from config", "profile_id", *opts.ProfileID)
	}

	// Governance: Validate the profile selection.
	if err := ectx.Policy.ValidateProfile(*opts.ProfileID); err != nil {
		log.Error("profile validation failed", "err", err, "profile_id", *opts.ProfileID)
		return EncryptResult{}, err
	}

	flags := buildEncryptFlags(opts)
	log.Debug("pipeline initializing", "flags", flags, "concurrency", *opts.Concurrency, "profile_id", *opts.ProfileID)

	// Measure input size for progress events.
	var totalBytes int64
	if inputName != "-" && inputName != "" {
		safeInput := filepath.Clean(inputName)
		// Reject paths that escape upward regardless of form.
		if strings.HasPrefix(safeInput, "..") {
			return EncryptResult{}, &ErrIO{Path: inputName, Reason: "path traversal not permitted"}
		}
		if fi, err := os.Stat(safeInput); err == nil && !fi.IsDir() {
			totalBytes = fi.Size()
		}
	}
	ectx.Emit(EventEncryptionStarted{TotalBytes: totalBytes})

	// Open the source reader (file, stdin, archive wrap, or caller-provided).
	sourceReader, closeSource, err := openSourceReader(inputName, r, opts)
	if err != nil {
		return EncryptResult{}, err
	}
	if closeSource != nil {
		defer closeSource()
	}

	if *opts.Compress {
		sourceReader = wrapWithCompressor(sourceReader, nil)
	}

	if err := dispatchEncrypt(sourceReader, w, flags, opts, ectx); err != nil {
		return EncryptResult{}, err
	}

	return EncryptResult{
		Status:     "success",
		Output:     inputName,
		Flags:      flags,
		ProfileID:  *opts.ProfileID,
		Compressed: *opts.Compress,
		IsArchive:  opts.IsArchive,
		IsSigned:   len(opts.SigningKey) > 0,
		IsStealth:  *opts.Stealth,
	}, nil
}

// resolvePipelineOptions fills in nil option fields from engine configuration defaults.
func (e *Engine) resolvePipelineOptions(ectx *EngineContext, opts *Options) {
	if opts.Concurrency == nil {
		opts.Concurrency = &e.Config.Performance.Concurrency
	}
	*opts.Concurrency = ectx.Policy.ClampConcurrency(*opts.Concurrency, e.Config.AgentLimits.MaxWorkers)

	if opts.Compress == nil {
		opts.Compress = &e.Config.Performance.DefaultCompress
	}

	if opts.Stealth == nil {
		opts.Stealth = &e.Config.Performance.DefaultStealth
	}

	if opts.ProfileID == nil {
		opts.ProfileID = &e.Config.Performance.DefaultProfile
	}
}

// openSourceReader resolves the io.Reader for encryption from inputName or r.
// When a file is opened internally, the returned closer must be called to release it.
func openSourceReader(inputName string, r io.Reader, opts Options) (io.Reader, func(), error) {
	if r != nil {
		return r, nil, nil
	}
	if opts.IsArchive {
		return wrapWithArchiver(inputName, nil), nil, nil
	}
	if inputName == "-" {
		return os.Stdin, nil, nil
	}
	safeInput := filepath.Clean(inputName)
	if strings.HasPrefix(safeInput, "..") {
		return nil, nil, &ErrIO{Path: inputName, Reason: "path traversal not permitted"}
	}
	f, err := os.Open(safeInput)
	if err != nil {
		return nil, nil, &ErrIO{Path: safeInput, Reason: err.Error()}
	}
	return f, func() { _ = f.Close() }, nil
}

// buildEncryptFlags assembles the V1 flags byte from resolved options.
func buildEncryptFlags(opts Options) byte {
	var flags byte
	if opts.IsArchive {
		flags |= FlagArchive
	}
	if *opts.Compress {
		flags |= FlagCompress
	}
	if *opts.Stealth {
		flags |= FlagStealth
	}
	return flags
}

// buildEncryptFlagsV2 assembles the V2 uint16 flags from resolved options.
// V1 flag bit values are preserved in the low byte.
func buildEncryptFlagsV2(opts Options) uint16 {
	return uint16(buildEncryptFlags(opts))
}

// useV2Format reports whether opts requests the V2 wire format.
// V2 is the default (FormatVersion 0 or 2). Exceptions that force V1:
//   - FormatVersion == 1 (explicit --v1 flag)
//   - Stealth mode: V2 always writes the magic header; stealth-mode V2 detection
//     requires additional framing that is reserved for a future release.
//   - Session key: the pre-derived-key path has a V1-only header structure.
func useV2Format(opts Options) bool {
	if opts.FormatVersion == 1 {
		return false
	}
	if opts.Stealth != nil && *opts.Stealth {
		return false // stealth + V2 reserved for future release
	}
	return true
}

// dispatchEncrypt routes to the correct encrypt function based on key material and format version.
//
// V2 (MAK2/MAK3) is the default. Pass FormatVersion=1 in opts to force the legacy V1
// format — necessary only when the receiver cannot upgrade to handle V2 files.
//
// Note: the session-key path always uses V1 because EncryptStreamWithKey encodes the
// pre-derived key directly; a V2 variant will be added in a future release.
func dispatchEncrypt(r io.Reader, w io.Writer, flags byte, opts Options, ectx *EngineContext) error {
	allPublicKeys := opts.Recipients
	if len(opts.PublicKey) > 0 {
		allPublicKeys = append(allPublicKeys, opts.PublicKey)
	}

	// Session-key path: always V1 (pre-derived key, no KDF, different header).
	if len(opts.SessionKey) > 0 {
		return EncryptStreamWithKey(r, w, opts.SessionKey, opts.SessionSalt, flags, *opts.Concurrency, *opts.ProfileID)
	}

	if useV2Format(opts) {
		v2flags := buildEncryptFlagsV2(opts)
		if len(allPublicKeys) > 0 {
			return EncryptStreamAsymV2(r, w, allPublicKeys, opts.SigningKey, v2flags, nil, *opts.Concurrency, *opts.ProfileID, ectx)
		}
		return EncryptStreamV2(r, w, opts.Passphrase, v2flags, nil, *opts.Concurrency, *opts.ProfileID, ectx)
	}

	// V1 legacy path.
	if len(allPublicKeys) > 0 {
		return EncryptStreamWithPublicKeysAndEvents(r, w, allPublicKeys, opts.SigningKey, flags, *opts.Concurrency, *opts.ProfileID, ectx)
	}
	return EncryptStreamWithEvents(r, w, opts.Passphrase, flags, *opts.Concurrency, *opts.ProfileID, ectx)
}

// Unprotect handles the full decryption pipeline: Handshake -> Decrypt -> Decompress -> Extract.
func (e *Engine) UnprotectStream(ectx *EngineContext, r io.Reader, w io.Writer, outPath string, opts Options) (DecryptResult, error) {
	ectx = e.context(ectx)
	traceID := opts.TraceID
	if traceID == "" {
		traceID = GenerateTraceID()
	}
	ectx.TraceID = traceID
	log := e.Logger.With("trace_id", traceID, "action", "unprotect", "output", outPath)

	if opts.EventStream != nil && ectx.Events == nil {
		ectx.Events = opts.EventStream
	}

	if outPath != "-" && outPath != "" {
		if err := ectx.Policy.ValidatePath(outPath); err != nil {
			log.Error("path validation failed", "err", err)
			return DecryptResult{}, err
		}
	}

	if opts.Concurrency == nil {
		opts.Concurrency = &e.Config.Performance.Concurrency
	}
	*opts.Concurrency = ectx.Policy.ClampConcurrency(*opts.Concurrency, e.Config.AgentLimits.MaxWorkers)

	if opts.Stealth == nil {
		opts.Stealth = &e.Config.Performance.DefaultStealth
	}

	flags, err := e.unprotectInternal(ectx, r, w, outPath, opts, log)
	if err != nil {
		return DecryptResult{}, err
	}

	return DecryptResult{
		Status: "success",
		Output: outPath,
		Flags:  flags,
	}, nil
}

func (e *Engine) unprotectInternal(ectx *EngineContext, r io.Reader, w io.Writer, outPath string, opts Options, log *slog.Logger) (byte, error) {
	log.Debug("restoration pipeline starting")
	ectx.Emit(EventDecryptionStarted{TotalBytes: opts.TotalSize})

	// 1. Peek at the header to determine flags
	magic, profileID, flags, recipientCount, err := ReadHeader(r, *opts.Stealth)
	if err != nil {
		return 0, err
	}

	// Governance: Validate discovered profile.
	// For V2 (MAK2/MAK3), ReadHeader returns profileID=0 (placeholder) because
	// the real ProfileID is inside the V2 header after the magic bytes.
	// Skip validation here; the V2 decoder will validate the actual profileID.
	isV2 := magic == MagicHeaderV2Sym || magic == MagicHeaderV2Asym
	if !isV2 {
		if err := ectx.Policy.ValidateProfile(profileID); err != nil {
			log.Error("profile validation failed during restoration", "err", err, "profile_id", profileID)
			return 0, err
		}
	}

	switch magic {
	case MagicHeaderSym:
		log.Debug("handshake complete", "mode", "symmetric_v1")
	case MagicHeaderAsym:
		log.Debug("handshake complete", "mode", "asymmetric_v1", "recipients", recipientCount)
	case MagicHeaderV2Sym:
		log.Debug("handshake complete", "mode", "symmetric_v2")
	case MagicHeaderV2Asym:
		log.Debug("handshake complete", "mode", "asymmetric_v2")
	}

	// Reconstruct the reader by prepending bytes consumed by ReadHeader.
	// V1: ReadHeader consumed magic(4) + profileID(1) + flags(1) [+ recipientCount(1) for asym].
	// V2: ReadHeader consumed only magic(4) and returned early — profileID/flags are 0 placeholders.
	var headerBytes []byte
	switch {
	case magic == MagicHeaderV2Sym || magic == MagicHeaderV2Asym:
		// Only the 4-byte magic was consumed; the rest (FormatVersion, ProfileID,
		// Flags, TLVs, …) are intact in r and will be parsed by the V2 decoder.
		headerBytes = []byte(magic)
	case !*opts.Stealth:
		headerBytes = append([]byte(magic), profileID, flags)
		if magic == MagicHeaderAsym {
			headerBytes = append(headerBytes, recipientCount)
		}
	default:
		headerBytes = []byte{profileID, flags}
	}
	fullIn := io.MultiReader(bytes.NewReader(headerBytes), r)

	// 2. Core Decryption + Post-Processing.
	//
	// V2 symmetric (MAK2): parse the header synchronously to extract the real
	// flags (compress, archive) before FinalizeRestoration starts. The flags
	// field returned by ReadHeader is 0 for V2 (early-exit placeholder) so we
	// must get them from ParseV2SymHeader.
	if magic == MagicHeaderV2Sym {
		v2hdr, parseErr := ParseV2SymHeader(fullIn, opts.Passphrase)
		if parseErr != nil {
			return 0, parseErr
		}
		ectx.Emit(EventHandshakeComplete{}) // header parsed and MAC verified
		realFlags := byte(v2hdr.Flags)
		pr, pw := io.Pipe()
		go func() {
			pw.CloseWithError(streamDecryptV2(fullIn, pw, v2hdr.AEAD, v2hdr.BaseNonce, ectx))
		}()
		if err = e.FinalizeRestoration(ectx, pr, w, realFlags, outPath, log); err != nil {
			return realFlags, err
		}
		return realFlags, nil
	}

	// V2 asymmetric (MAK3): parse header synchronously to get real flags.
	if magic == MagicHeaderV2Asym {
		v2hdr, parseErr := ParseV2AsymHeader(fullIn, opts.LocalPrivateKey)
		if parseErr != nil {
			return 0, parseErr
		}
		ectx.Emit(EventHandshakeComplete{})
		realFlags := byte(v2hdr.Flags)
		pr, pw := io.Pipe()
		go func() {
			pw.CloseWithError(streamDecryptV2(fullIn, pw, v2hdr.AEAD, v2hdr.BaseNonce, ectx))
		}()
		if err = e.FinalizeRestoration(ectx, pr, w, realFlags, outPath, log); err != nil {
			return realFlags, err
		}
		return realFlags, nil
	}

	pr, pw := io.Pipe()
	concurrency := *opts.Concurrency
	stealth := *opts.Stealth
	go func() {
		defer pw.Close()
		var dErr error
		if magic == MagicHeaderAsym {
			_, _, dErr = DecryptStreamWithPrivateKeyAndEvents(fullIn, pw, opts.LocalPrivateKey, opts.PublicKey, concurrency, stealth, ectx)
		} else if len(opts.SessionKey) > 0 {
			_, _, dErr = DecryptStreamWithKey(fullIn, pw, opts.SessionKey, concurrency, stealth)
		} else {
			_, _, dErr = DecryptStreamWithEvents(fullIn, pw, opts.Passphrase, concurrency, stealth, ectx)
		}

		if dErr != nil {
			_ = pw.CloseWithError(dErr)
		}
	}()

	// 3. Finalize Post-Processing (Decompress -> Extract)
	err = e.FinalizeRestoration(ectx, pr, w, flags, outPath, log)
	if err != nil {
		return flags, err
	}

	return flags, nil
}

// --- Helpers for Options ---

func BoolPtr(b bool) *bool { return &b }
func IntPtr(i int) *int    { return &i }
func BytePtr(b byte) *byte { return &b }

// --- Legacy Shims ---

// Protect handles the full encryption pipeline for a source (file, directory, or reader).
// This is a package-level shim that uses a crypto-only engine (no vault/identity/network).
// Prefer constructing an Engine via NewStreamEngine and calling Protect directly.
func Protect(inputName string, r io.Reader, w io.Writer, opts Options) (byte, error) {
	ectx := &EngineContext{
		Context: context.Background(),
		Events:  opts.EventStream,
		Policy:  &HumanPolicy{},
	}

	// Temporarily bypass pipeline for legacy shim to avoid circular return type issues
	// or use a dummy Engine if needed. Better: reuse protectInternal-like logic
	if opts.ProfileID != nil && *opts.ProfileID != 0 {
		if _, err := GetProfile(*opts.ProfileID, nil); err != nil {
			return 0, err
		}
	}

	e := NewStreamEngine(nil)
	res, err := e.Protect(ectx, inputName, r, w, opts)
	return res.Flags, err
}

// Unprotect handles the full decryption pipeline: Handshake -> Decrypt -> Decompress -> Extract.
// This is a package-level shim that uses a crypto-only engine (no vault/identity/network).
// Prefer constructing an Engine via NewStreamEngine and calling Unprotect directly.
func Unprotect(r io.Reader, w io.Writer, outPath string, opts Options) (byte, error) {
	ectx := &EngineContext{
		Context: context.Background(),
		Events:  opts.EventStream,
		Policy:  &HumanPolicy{},
	}

	e := NewStreamEngine(nil)
	res, err := e.Unprotect(ectx, r, w, outPath, opts)
	return res.Flags, err
}

// FinalizeRestoration handles the post-decryption steps: decompression and archive extraction.
func (e *Engine) FinalizeRestoration(ectx *EngineContext, pr io.Reader, w io.Writer, flags byte, outPath string, log *slog.Logger) error {
	var decReader io.Reader = pr
	if flags&FlagCompress != 0 {
		log.Debug("decompressing zstd stream")
		zr, err := zstd.NewReader(pr)
		if err != nil {
			return &ErrCrypto{Reason: fmt.Sprintf("failed to initialize zstd reader: %v", err)}
		}
		defer zr.Close()
		decReader = zr
	}

	if flags&FlagArchive != 0 {
		log.Debug("extracting tar archive", "target", outPath)
		if err := ExtractArchive(decReader, outPath); err != nil {
			return &ErrIO{Path: outPath, Reason: fmt.Sprintf("failed to extract archive: %v", err)}
		}
		return nil
	}

	var out io.Writer
	if w != nil {
		out = w
	} else if outPath == "-" {
		out = os.Stdout
	} else if outPath != "" {
		safeOut := filepath.Clean(outPath)
		if strings.HasPrefix(safeOut, "..") {
			return &ErrIO{Path: outPath, Reason: "path traversal not permitted"}
		}
		if err := os.MkdirAll(filepath.Dir(safeOut), 0750); err != nil {
			return &ErrIO{Path: filepath.Dir(safeOut), Reason: err.Error()}
		}
		f, err := os.Create(safeOut)
		if err != nil {
			return &ErrIO{Path: safeOut, Reason: err.Error()}
		}
		defer func() { _ = f.Close() }()
		out = f
	}

	if out != nil {
		if _, err := io.Copy(out, decReader); err != nil {
			return &ErrIO{Path: "output", Reason: err.Error()}
		}
	}
	return nil
}

// CompressStream wraps a reader with a Zstd compressor.
func CompressStream(r io.Reader, w io.Writer) error {
	zw, err := zstd.NewWriter(w)
	if err != nil {
		return err
	}
	defer zw.Close()
	_, err = io.Copy(zw, r)
	return err
}

// DecompressStream wraps a reader with a Zstd decompressor.
func DecompressStream(r io.Reader, w io.Writer) error {
	zr, err := zstd.NewReader(r)
	if err != nil {
		return err
	}
	defer zr.Close()
	_, err = io.Copy(w, zr)
	return err
}

func wrapWithArchiver(inputName string, logger *slog.Logger) io.Reader {
	pr, pw := io.Pipe()
	go func() {
		var walkErr error
		defer func() {
			_ = pw.CloseWithError(walkErr)
		}()

		tw := tar.NewWriter(pw)
		defer func() { _ = tw.Close() }()

		baseDir := filepath.Dir(filepath.Clean(inputName))
		walkErr = filepath.Walk(inputName, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(baseDir, path)
			if err != nil {
				return err
			}
			header, err := tar.FileInfoHeader(info, "")
			if err != nil {
				return err
			}
			header.Name = rel
			if err := tw.WriteHeader(header); err != nil {
				return err
			}
			if !info.IsDir() {
				f, err := os.Open(path)
				if err != nil {
					return err
				}
				defer func() { _ = f.Close() }()
				_, err = io.Copy(tw, f)
				return err
			}
			return nil
		})
	}()
	return pr
}

func wrapWithCompressor(r io.Reader, logger *slog.Logger) io.Reader {
	pr, pw := io.Pipe()
	go func() {
		var zErr error
		defer func() {
			_ = pw.CloseWithError(zErr)
		}()
		zw, _ := zstd.NewWriter(pw)
		defer func() { _ = zw.Close() }()
		_, zErr = io.Copy(zw, r)
	}()
	return pr
}

// ExtractArchive takes a decrypted tar stream and extracts it to the target directory.
func ExtractArchive(r io.Reader, outputDir string) error {
	// filepath.Abs already calls filepath.Clean internally; we call Clean again
	// explicitly so that CodeQL's taint analysis sees the sanitised variable.
	absOutputDir, err := filepath.Abs(filepath.Clean(outputDir))
	if err != nil {
		return &ErrIO{Path: outputDir, Reason: "invalid output directory"}
	}

	if outputDir != "" {
		if err := os.MkdirAll(absOutputDir, 0750); err != nil {
			return &ErrIO{Path: absOutputDir, Reason: err.Error()}
		}
	}
	tr := tar.NewReader(r)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return &ErrFormat{Reason: fmt.Sprintf("failed to read tar header: %v", err)}
		}

		target := filepath.Join(absOutputDir, h.Name)
		rel, err := filepath.Rel(absOutputDir, target)
		if err != nil || strings.HasPrefix(rel, "..") {
			return &ErrPolicyViolation{Reason: "illegal file path in archive", Path: h.Name}
		}

		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0750); err != nil {
				return &ErrIO{Path: target, Reason: err.Error()}
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0750); err != nil {
				return &ErrIO{Path: filepath.Dir(target), Reason: err.Error()}
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_RDWR|os.O_TRUNC, os.FileMode(h.Mode))
			if err != nil {
				return &ErrIO{Path: target, Reason: err.Error()}
			}
			/* #nosec G110 */
			if _, err = io.Copy(f, tr); err != nil {
				_ = f.Close()
				return &ErrIO{Path: target, Reason: err.Error()}
			}
			if err = f.Close(); err != nil {
				return &ErrIO{Path: target, Reason: err.Error()}
			}
		}
	}
	return nil
}

func Sha256Sum(data []byte) []byte {
	h := sha256.New()
	h.Write(data)
	return h.Sum(nil)
}
