package password

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2Config holds the configuration for Argon2id hashing.
type Argon2Config struct {
	// Memory is the amount of memory used in KiB.
	Memory uint32

	// Iterations is the number of passes over the memory.
	Iterations uint32

	// Parallelism is the number of threads to use.
	Parallelism uint8

	// SaltLength is the length of the random salt in bytes.
	SaltLength uint32

	// KeyLength is the length of the generated key in bytes.
	KeyLength uint32
}

// DefaultArgon2Config returns secure default parameters for Argon2id.
// These follow OWASP recommendations for password storage.
func DefaultArgon2Config() *Argon2Config {
	return &Argon2Config{
		Memory:      64 * 1024, // 64 MiB
		Iterations:  3,
		Parallelism: 2,
		SaltLength:  16,
		KeyLength:   32,
	}
}

// Argon2Hasher implements the Hasher interface using Argon2id.
type Argon2Hasher struct {
	config *Argon2Config
}

// NewArgon2Hasher creates a new Argon2id hasher with the given configuration.
// If config is nil, DefaultArgon2Config is used.
func NewArgon2Hasher(config *Argon2Config) *Argon2Hasher {
	if config == nil {
		config = DefaultArgon2Config()
	}
	return &Argon2Hasher{config: config}
}

// Hash creates an Argon2id hash from a password.
// Returns the hash in PHC string format: $argon2id$v=19$m=65536,t=3,p=2$salt$hash
func (h *Argon2Hasher) Hash(password string) (string, error) {
	salt := make([]byte, h.config.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	hash := argon2.IDKey(
		[]byte(password),
		salt,
		h.config.Iterations,
		h.config.Memory,
		h.config.Parallelism,
		h.config.KeyLength,
	)

	// Encode to PHC string format
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	encoded := fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		h.config.Memory,
		h.config.Iterations,
		h.config.Parallelism,
		b64Salt,
		b64Hash,
	)

	return encoded, nil
}

// Verify checks if a password matches an Argon2id hash.
func (h *Argon2Hasher) Verify(password, encodedHash string) (bool, error) {
	config, salt, hash, err := decodeArgon2Hash(encodedHash)
	if err != nil {
		return false, err
	}

	otherHash := argon2.IDKey(
		[]byte(password),
		salt,
		config.Iterations,
		config.Memory,
		config.Parallelism,
		config.KeyLength,
	)

	// Constant-time comparison to prevent timing attacks
	if subtle.ConstantTimeCompare(hash, otherHash) == 1 {
		return true, nil
	}
	return false, nil
}

// NeedsRehash checks if a hash was created with different parameters.
func (h *Argon2Hasher) NeedsRehash(encodedHash string) bool {
	config, _, _, err := decodeArgon2Hash(encodedHash)
	if err != nil {
		return true
	}

	return config.Memory != h.config.Memory ||
		config.Iterations != h.config.Iterations ||
		config.Parallelism != h.config.Parallelism ||
		config.KeyLength != h.config.KeyLength
}

// decodeArgon2Hash parses an Argon2id hash in PHC string format.
func decodeArgon2Hash(encodedHash string) (*Argon2Config, []byte, []byte, error) {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 {
		return nil, nil, nil, errors.New("invalid hash format")
	}

	if parts[1] != "argon2id" {
		return nil, nil, nil, errors.New("unsupported algorithm")
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return nil, nil, nil, err
	}
	if version != argon2.Version {
		return nil, nil, nil, errors.New("incompatible argon2 version")
	}

	config := &Argon2Config{}
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d",
		&config.Memory, &config.Iterations, &config.Parallelism); err != nil {
		return nil, nil, nil, err
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, nil, nil, err
	}
	config.SaltLength = uint32(len(salt)) //nolint:gosec // salt length is bounded by base64 decode

	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return nil, nil, nil, err
	}
	config.KeyLength = uint32(len(hash)) //nolint:gosec // hash length is bounded by base64 decode

	return config, salt, hash, nil
}

// Ensure Argon2Hasher implements Hasher.
var _ Hasher = (*Argon2Hasher)(nil)
