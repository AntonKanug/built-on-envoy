// Copyright Built On Envoy
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package webterminal

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"github.com/tetratelabs/built-on-envoy/extensions/composer/pkg"
)

// Real-world vectors: bcryptVector is `htpasswd -nbB admin secret`, and
// pbkdf2Vector is the passlib pbkdf2_sha256 encoding for password "secret".
const (
	bcryptVector = "$2y$05$MSW705eMrxPRvItMsPH0YuNn995uaKFR.Er6kR1fzHHpT5Oo2bYvC"
	pbkdf2Vector = "$pbkdf2-sha256$29000$MDEyMzQ1Njc4OWFiY2RlZg$aQOdhWy9q87h1Y13loIh9irlXgv2WqcdeMcUgrd9rJ4"
)

// minCostHash generates a bcrypt hash at MinCost so tests stay fast.
func minCostHash(t *testing.T, password string) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	require.NoError(t, err)
	return string(h)
}

// basicHeader builds an "Authorization: Basic ..." header value.
func basicHeader(userPass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(userPass))
}

func testAuthenticator(t *testing.T, htpasswd string) *authenticator {
	t.Helper()
	a, err := newAuthenticator(&basicAuthConfig{
		Htpasswd: &pkg.DataSource{Inline: htpasswd},
		Realm:    defaultRealm,
	})
	require.NoError(t, err)
	return a
}

func TestParseHtpasswd(t *testing.T) {
	users, err := parseHtpasswd([]byte(
		"# a comment\n" +
			"\n" +
			"admin:" + bcryptVector + "\r\n" +
			"  fips:" + pbkdf2Vector + "  \n"))
	require.NoError(t, err)
	require.Len(t, users, 2)
	require.IsType(t, bcryptCredential(nil), users["admin"])
	require.IsType(t, &pbkdf2Credential{}, users["fips"])
}

func TestParseHtpasswdErrors(t *testing.T) {
	tests := []struct {
		name    string
		data    string
		wantErr string
	}{
		{"no colon", "adminnocolon", "line 1: expected user:hash"},
		{"empty user", ":" + bcryptVector, "line 1: expected user:hash"},
		{"empty hash", "admin:", "line 1: expected user:hash"},
		{"duplicate user", "a:" + bcryptVector + "\na:" + bcryptVector, `line 2: duplicate user "a"`},
		{"apr1 rejected", "a:$apr1$x$y", "line 1"},
		{"sha rejected", "a:{SHA}2aae6c35c94fcfb415dbe95f408b9ce91ee846ed", "line 1"},
		{"plaintext rejected", "a:hunter2", "line 1"},
		{"truncated bcrypt", "a:$2y$05$short", "invalid bcrypt hash"},
		{"empty file", "", "no users"},
		{"comments only", "# nothing\n\n", "no users"},
		{"error on later line", "a:" + bcryptVector + "\nb:$apr1$x$y", "line 2"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseHtpasswd([]byte(tt.data))
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestParsePasslibPBKDF2(t *testing.T) {
	cred, err := parsePasslibPBKDF2(pbkdf2Vector)
	require.NoError(t, err)
	require.Equal(t, 29000, cred.iterations)
	require.Equal(t, []byte("0123456789abcdef"), cred.salt)
	require.Len(t, cred.hash, 32)
	require.True(t, cred.verify([]byte("secret")))
	require.False(t, cred.verify([]byte("wrong")))

	for name, hash := range map[string]string{
		"wrong part count":       "$pbkdf2-sha256$29000$c2FsdA",
		"non-numeric iterations": "$pbkdf2-sha256$many$c2FsdA$" + pbkdf2Vector[len(pbkdf2Vector)-43:],
		"zero iterations":        "$pbkdf2-sha256$0$c2FsdA$" + pbkdf2Vector[len(pbkdf2Vector)-43:],
		"excessive iterations":   fmt.Sprintf("$pbkdf2-sha256$%d$c2FsdA$%s", maxPBKDF2Iterations+1, pbkdf2Vector[len(pbkdf2Vector)-43:]),
		"empty salt":             "$pbkdf2-sha256$29000$$" + pbkdf2Vector[len(pbkdf2Vector)-43:],
		"bad base64 salt":        "$pbkdf2-sha256$29000$!!$" + pbkdf2Vector[len(pbkdf2Vector)-43:],
		"bad base64 checksum":    "$pbkdf2-sha256$29000$c2FsdA$!!",
		"short checksum":         "$pbkdf2-sha256$29000$c2FsdA$c2FsdA",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := parsePasslibPBKDF2(hash)
			require.Error(t, err)
		})
	}
}

func TestDecodeAdaptedBase64(t *testing.T) {
	// "." maps to "+": std base64 "+w" decodes like adapted ".w".
	std, err := base64.StdEncoding.WithPadding(base64.NoPadding).DecodeString("+w")
	require.NoError(t, err)
	got, err := decodeAdaptedBase64(".w")
	require.NoError(t, err)
	require.Equal(t, std, got)

	_, err = decodeAdaptedBase64("!!")
	require.Error(t, err)
	// Padded input is not the passlib encoding.
	_, err = decodeAdaptedBase64("c2FsdA==")
	require.Error(t, err)
}

func TestAuthenticate(t *testing.T) {
	a := testAuthenticator(t,
		"admin:"+minCostHash(t, "secret")+"\n"+
			"colons:"+minCostHash(t, "pa:ss:wd")+"\n"+
			"fips:"+pbkdf2Vector)

	tests := []struct {
		name   string
		header string
		want   bool
	}{
		{"valid bcrypt", basicHeader("admin:secret"), true},
		{"valid pbkdf2", basicHeader("fips:secret"), true},
		{"password with colons", basicHeader("colons:pa:ss:wd"), true},
		{"lowercase scheme", "basic " + base64.StdEncoding.EncodeToString([]byte("admin:secret")), true},
		{"wrong password", basicHeader("admin:wrong"), false},
		{"unknown user", basicHeader("nobody:secret"), false},
		{"empty header", "", false},
		{"bearer scheme", "Bearer abc", false},
		{"bad base64", "Basic !!!", false},
		{"no colon in payload", "Basic " + base64.StdEncoding.EncodeToString([]byte("adminsecret")), false},
		{"scheme only", "Basic ", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, a.authenticate(tt.header))
		})
	}
}

// countingCredential records how many times the slow path runs.
type countingCredential struct {
	calls    int
	password string
}

func (c *countingCredential) verify(password []byte) bool {
	c.calls++
	return string(password) == c.password
}

func TestAuthenticateCache(t *testing.T) {
	a := testAuthenticator(t, "seed:"+minCostHash(t, "x"))
	cred := &countingCredential{password: "secret"}
	a.users["admin"] = cred

	// First success verifies slowly and caches; the second hits the cache.
	require.True(t, a.authenticate(basicHeader("admin:secret")))
	require.Equal(t, 1, cred.calls)
	require.True(t, a.authenticate(basicHeader("admin:secret")))
	require.Equal(t, 1, cred.calls)

	// A warm cache does not admit wrong credentials or other users.
	require.False(t, a.authenticate(basicHeader("admin:wrong")))
	require.Equal(t, 2, cred.calls)
	require.False(t, a.authenticate(basicHeader("seed:secret")))

	// Failed attempts never populate the cache.
	require.Len(t, a.verified, 1)
}

func TestNewAuthenticator(t *testing.T) {
	htpasswd := "admin:" + bcryptVector + "\n"

	a, err := newAuthenticator(&basicAuthConfig{Htpasswd: &pkg.DataSource{Inline: htpasswd}, Realm: "r"})
	require.NoError(t, err)
	require.Equal(t, "r", a.realm)
	require.Len(t, a.users, 1)

	path := filepath.Join(t.TempDir(), "htpasswd")
	require.NoError(t, os.WriteFile(path, []byte(htpasswd), 0o600))
	a, err = newAuthenticator(&basicAuthConfig{Htpasswd: &pkg.DataSource{File: path}, Realm: "r"})
	require.NoError(t, err)
	require.Len(t, a.users, 1)

	_, err = newAuthenticator(&basicAuthConfig{Htpasswd: &pkg.DataSource{File: filepath.Join(t.TempDir(), "missing")}})
	require.ErrorContains(t, err, "failed to load htpasswd data")

	_, err = newAuthenticator(&basicAuthConfig{Htpasswd: &pkg.DataSource{Inline: "garbage"}})
	require.Error(t, err)
}

func TestNewAuthenticatorUsers(t *testing.T) {
	// Plaintext users authenticate like any other credential.
	a, err := newAuthenticator(&basicAuthConfig{Users: map[string]string{"admin": "secret"}, Realm: "r"})
	require.NoError(t, err)
	require.True(t, a.authenticate(basicHeader("admin:secret")))
	require.False(t, a.authenticate(basicHeader("admin:wrong")))

	// Both sources merge.
	a, err = newAuthenticator(&basicAuthConfig{
		Htpasswd: &pkg.DataSource{Inline: "admin:" + bcryptVector},
		Users:    map[string]string{"extra": "pw"},
		Realm:    "r",
	})
	require.NoError(t, err)
	require.Len(t, a.users, 2)
	require.True(t, a.authenticate(basicHeader("extra:pw")))

	// A user defined in both sources is ambiguous.
	_, err = newAuthenticator(&basicAuthConfig{
		Htpasswd: &pkg.DataSource{Inline: "admin:" + bcryptVector},
		Users:    map[string]string{"admin": "pw"},
	})
	require.ErrorContains(t, err, `user "admin" is also defined`)

	// Empty names, names with colons, and empty passwords are config mistakes.
	_, err = newAuthenticator(&basicAuthConfig{Users: map[string]string{"": "pw"}})
	require.Error(t, err)
	_, err = newAuthenticator(&basicAuthConfig{Users: map[string]string{"a:b": "pw"}})
	require.Error(t, err)
	_, err = newAuthenticator(&basicAuthConfig{Users: map[string]string{"admin": ""}})
	require.ErrorContains(t, err, "password must not be empty")

	// No source at all yields no users.
	_, err = newAuthenticator(&basicAuthConfig{})
	require.ErrorContains(t, err, "no users")
}
