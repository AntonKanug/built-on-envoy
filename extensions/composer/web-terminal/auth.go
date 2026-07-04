// Copyright Built On Envoy
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package webterminal

import (
	"bufio"
	"bytes"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/crypto/bcrypt"
)

// maxPBKDF2Iterations guards against config typos that would make every
// verification take seconds; it is not a security boundary (the config
// author already controls the hash).
const maxPBKDF2Iterations = 10_000_000

const unsupportedHashHint = `unsupported hash format (supported: bcrypt "$2a$/$2b$/$2y$" from htpasswd -B, and "$pbkdf2-sha256$" passlib format)`

// credential is one parsed htpasswd password verifier.
type credential interface {
	verify(password []byte) bool
}

type bcryptCredential []byte

func (c bcryptCredential) verify(password []byte) bool {
	return bcrypt.CompareHashAndPassword(c, password) == nil
}

type pbkdf2Credential struct {
	iterations int
	salt, hash []byte
}

func (c *pbkdf2Credential) verify(password []byte) bool {
	dk, err := pbkdf2.Key(sha256.New, string(password), c.salt, c.iterations, len(c.hash))
	return err == nil && subtle.ConstantTimeCompare(dk, c.hash) == 1
}

// plaintextCredential holds the SHA-256 of a password from the config "users"
// map, so the clear text is not kept in memory and the compare is
// constant-time over fixed-size digests.
type plaintextCredential [sha256.Size]byte

func (c plaintextCredential) verify(password []byte) bool {
	digest := sha256.Sum256(password)
	return subtle.ConstantTimeCompare(c[:], digest[:]) == 1
}

// parseHtpasswd parses "user:hash" lines. Blank lines and lines starting with
// "#" are skipped. Only bcrypt and passlib PBKDF2-SHA256 hashes are accepted;
// anything else fails so misconfiguration surfaces at config load, not as
// mysterious 401s.
func parseHtpasswd(data []byte) (map[string]credential, error) {
	users := make(map[string]credential)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for n := 1; scanner.Scan(); n++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		user, hash, ok := strings.Cut(line, ":")
		if !ok || user == "" || hash == "" {
			return nil, fmt.Errorf("htpasswd line %d: expected user:hash", n)
		}
		if _, dup := users[user]; dup {
			return nil, fmt.Errorf("htpasswd line %d: duplicate user %q", n, user)
		}
		cred, err := parseCredential(hash)
		if err != nil {
			return nil, fmt.Errorf("htpasswd line %d: user %q: %w", n, user, err)
		}
		users[user] = cred
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read htpasswd data: %w", err)
	}
	if len(users) == 0 {
		return nil, fmt.Errorf("htpasswd contains no users")
	}
	return users, nil
}

func parseCredential(hash string) (credential, error) {
	switch {
	case strings.HasPrefix(hash, "$2a$"), strings.HasPrefix(hash, "$2b$"), strings.HasPrefix(hash, "$2y$"):
		if _, err := bcrypt.Cost([]byte(hash)); err != nil {
			return nil, fmt.Errorf("invalid bcrypt hash: %w", err)
		}
		return bcryptCredential(hash), nil
	case strings.HasPrefix(hash, "$pbkdf2-sha256$"):
		return parsePasslibPBKDF2(hash)
	default:
		return nil, fmt.Errorf("%s", unsupportedHashHint)
	}
}

// parsePasslibPBKDF2 parses "$pbkdf2-sha256$<iterations>$<salt>$<checksum>"
// where salt and checksum use passlib's adapted base64.
func parsePasslibPBKDF2(s string) (*pbkdf2Credential, error) {
	parts := strings.Split(s, "$")
	if len(parts) != 5 { // ["", "pbkdf2-sha256", iterations, salt, checksum]
		return nil, fmt.Errorf("invalid pbkdf2-sha256 hash: expected $pbkdf2-sha256$<iterations>$<salt>$<checksum>")
	}
	iterations, err := strconv.Atoi(parts[2])
	if err != nil || iterations <= 0 {
		return nil, fmt.Errorf("invalid pbkdf2-sha256 hash: bad iteration count %q", parts[2])
	}
	if iterations > maxPBKDF2Iterations {
		return nil, fmt.Errorf("invalid pbkdf2-sha256 hash: iteration count %d exceeds the maximum of %d", iterations, maxPBKDF2Iterations)
	}
	salt, err := decodeAdaptedBase64(parts[3])
	if err != nil || len(salt) == 0 {
		return nil, fmt.Errorf("invalid pbkdf2-sha256 hash: bad salt")
	}
	hash, err := decodeAdaptedBase64(parts[4])
	if err != nil {
		return nil, fmt.Errorf("invalid pbkdf2-sha256 hash: bad checksum")
	}
	if len(hash) != sha256.Size {
		return nil, fmt.Errorf("invalid pbkdf2-sha256 hash: checksum must be %d bytes, got %d", sha256.Size, len(hash))
	}
	return &pbkdf2Credential{iterations: iterations, salt: salt, hash: hash}, nil
}

// decodeAdaptedBase64 decodes passlib's adapted base64: standard base64 with
// "." in place of "+" and no padding.
func decodeAdaptedBase64(s string) ([]byte, error) {
	return base64.StdEncoding.WithPadding(base64.NoPadding).DecodeString(strings.ReplaceAll(s, ".", "+"))
}

// authenticator verifies HTTP Basic credentials against parsed htpasswd
// users. One authenticator lives on the filter factory (like the session
// registry), so its cache lifetime equals the config lifetime and password
// rotation takes effect on config reload.
type authenticator struct {
	realm string
	users map[string]credential

	// dummy is a bcrypt hash of a random password, compared against on
	// unknown-user requests so their timing resembles a real user's first
	// attempt. Best-effort only: cached known-user requests are fast, so
	// full timing uniformity is not a goal.
	dummy []byte

	// verified caches, per user, the SHA-256 of the raw "user:password"
	// credential that passed slow verification, so per-keystroke /input
	// requests cost a hash compare instead of a ~50-100ms bcrypt. Failed
	// attempts never insert, bounding the map by the number of users.
	mu       sync.Mutex
	verified map[string][sha256.Size]byte
}

func newAuthenticator(cfg *basicAuthConfig) (*authenticator, error) {
	users := make(map[string]credential)
	if cfg.Htpasswd != nil {
		data, err := cfg.Htpasswd.Content()
		if err != nil {
			return nil, fmt.Errorf("failed to load htpasswd data: %w", err)
		}
		if users, err = parseHtpasswd(data); err != nil {
			return nil, err
		}
	}
	for user, password := range cfg.Users {
		if user == "" || strings.Contains(user, ":") {
			return nil, fmt.Errorf("users: user names must not be empty or contain ':'")
		}
		if password == "" {
			return nil, fmt.Errorf("users: user %q: password must not be empty", user)
		}
		if _, dup := users[user]; dup {
			return nil, fmt.Errorf("users: user %q is also defined in the htpasswd data", user)
		}
		users[user] = plaintextCredential(sha256.Sum256([]byte(password)))
	}
	if len(users) == 0 {
		return nil, fmt.Errorf("basic_auth has no users")
	}
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return nil, fmt.Errorf("failed to generate dummy credential: %w", err)
	}
	dummy, err := bcrypt.GenerateFromPassword(random, bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to generate dummy credential: %w", err)
	}
	return &authenticator{
		realm:    cfg.Realm,
		users:    users,
		dummy:    dummy,
		verified: make(map[string][sha256.Size]byte),
	}, nil
}

// authenticate reports whether the Authorization header value carries valid
// Basic credentials for a configured user.
func (a *authenticator) authenticate(authorization string) bool {
	const prefix = "Basic "
	if len(authorization) <= len(prefix) || !strings.EqualFold(authorization[:len(prefix)], prefix) {
		return false
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(authorization[len(prefix):]))
	if err != nil {
		return false
	}
	// Split on the first colon only: passwords may contain colons.
	user, pass, ok := bytes.Cut(decoded, []byte{':'})
	if !ok {
		return false
	}
	cred, found := a.users[string(user)]
	if !found {
		_ = bcrypt.CompareHashAndPassword(a.dummy, pass)
		return false
	}

	digest := sha256.Sum256(decoded)
	a.mu.Lock()
	cached, hasCached := a.verified[string(user)]
	a.mu.Unlock()
	if hasCached && subtle.ConstantTimeCompare(cached[:], digest[:]) == 1 {
		return true
	}

	if !cred.verify(pass) {
		return false
	}
	a.mu.Lock()
	a.verified[string(user)] = digest
	a.mu.Unlock()
	return true
}
