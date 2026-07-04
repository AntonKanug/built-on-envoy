// Copyright Built On Envoy
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package webterminal

import (
	"testing"

	internaltesting "github.com/tetratelabs/built-on-envoy/extensions/composer/internal/testing"
)

func TestConfigSchema(t *testing.T) {
	t.Run("empty config is valid (defaults apply)", func(t *testing.T) {
		internaltesting.AssertSchemaValid(t, "config.schema.json", `{}`)
	})
	t.Run("full config", func(t *testing.T) {
		internaltesting.AssertSchemaValid(t, "config.schema.json", `{
			"command": "/bin/bash",
			"args": ["-l"],
			"writable": false,
			"serve_frontend": true
		}`)
	})
	t.Run("empty command is invalid", func(t *testing.T) {
		internaltesting.AssertSchemaInvalid(t, "config.schema.json", `{"command": ""}`)
	})
	t.Run("unknown property is invalid", func(t *testing.T) {
		internaltesting.AssertSchemaInvalid(t, "config.schema.json", `{"nope": true}`)
	})
	t.Run("basic_auth with inline htpasswd", func(t *testing.T) {
		internaltesting.AssertSchemaValid(t, "config.schema.json",
			`{"basic_auth": {"htpasswd": {"inline": "admin:$2y$05$x"}}}`)
	})
	t.Run("basic_auth with htpasswd file and realm", func(t *testing.T) {
		internaltesting.AssertSchemaValid(t, "config.schema.json",
			`{"basic_auth": {"htpasswd": {"file": "/etc/envoy/htpasswd"}, "realm": "ops"}}`)
	})
	t.Run("basic_auth with users map", func(t *testing.T) {
		internaltesting.AssertSchemaValid(t, "config.schema.json",
			`{"basic_auth": {"users": {"admin": "secret", "bob": "pw"}}}`)
	})
	t.Run("basic_auth with users and htpasswd", func(t *testing.T) {
		internaltesting.AssertSchemaValid(t, "config.schema.json",
			`{"basic_auth": {"htpasswd": {"file": "/x"}, "users": {"admin": "secret"}}}`)
	})
	t.Run("basic_auth requires htpasswd or users", func(t *testing.T) {
		internaltesting.AssertSchemaInvalid(t, "config.schema.json", `{"basic_auth": {}}`)
	})
	t.Run("empty users map is invalid", func(t *testing.T) {
		internaltesting.AssertSchemaInvalid(t, "config.schema.json", `{"basic_auth": {"users": {}}}`)
	})
	t.Run("empty password in users is invalid", func(t *testing.T) {
		internaltesting.AssertSchemaInvalid(t, "config.schema.json",
			`{"basic_auth": {"users": {"admin": ""}}}`)
	})
	t.Run("user name with colon is invalid", func(t *testing.T) {
		internaltesting.AssertSchemaInvalid(t, "config.schema.json",
			`{"basic_auth": {"users": {"ad:min": "pw"}}}`)
	})
	t.Run("htpasswd with both inline and file is invalid", func(t *testing.T) {
		internaltesting.AssertSchemaInvalid(t, "config.schema.json",
			`{"basic_auth": {"htpasswd": {"inline": "a:b", "file": "/x"}}}`)
	})
	t.Run("htpasswd with neither inline nor file is invalid", func(t *testing.T) {
		internaltesting.AssertSchemaInvalid(t, "config.schema.json",
			`{"basic_auth": {"htpasswd": {}}}`)
	})
	t.Run("unknown property inside basic_auth is invalid", func(t *testing.T) {
		internaltesting.AssertSchemaInvalid(t, "config.schema.json",
			`{"basic_auth": {"htpasswd": {"inline": "a:b"}, "nope": true}}`)
	})
	t.Run("realm with a double quote is invalid", func(t *testing.T) {
		internaltesting.AssertSchemaInvalid(t, "config.schema.json",
			`{"basic_auth": {"htpasswd": {"inline": "a:b"}, "realm": "o\"ps"}}`)
	})
}
