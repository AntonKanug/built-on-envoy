// Copyright Built On Envoy
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package webterminal

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/envoyproxy/envoy/source/extensions/dynamic_modules/sdk/go/shared"
	"github.com/envoyproxy/envoy/source/extensions/dynamic_modules/sdk/go/shared/fake"
	"github.com/envoyproxy/envoy/source/extensions/dynamic_modules/sdk/go/shared/mocks"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// syncScheduler runs scheduled functions inline so tests observe SendResponseData
// deterministically.
type syncScheduler struct{}

func (syncScheduler) Schedule(f func()) { f() }

type frame struct {
	data []byte
	end  bool
}

func newHandle(ctrl *gomock.Controller) *mocks.MockHttpFilterHandle {
	h := mocks.NewMockHttpFilterHandle(ctrl)
	h.EXPECT().Log(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
	return h
}

func headerMap(method, path string) shared.HeaderMap {
	return fake.NewFakeHeaderMap(map[string][]string{":method": {method}, ":path": {path}})
}

func headerMapWithAuth(method, path, authorization string) shared.HeaderMap {
	headers := map[string][]string{":method": {method}, ":path": {path}}
	if authorization != "" {
		headers["authorization"] = []string{authorization}
	}
	return fake.NewFakeHeaderMap(headers)
}

func TestParseConfig(t *testing.T) {
	cfg, err := parseConfig(nil)
	require.NoError(t, err)
	require.Equal(t, "/bin/bash", cfg.Command)
	require.True(t, cfg.Writable)
	require.Nil(t, cfg.ServeFrontend) // frontend on by default

	cfg, err = parseConfig([]byte(`{"command":"sh","args":["-c","x"],"writable":false,"serve_frontend":true}`))
	require.NoError(t, err)
	require.Equal(t, "sh", cfg.Command)
	require.Equal(t, []string{"-c", "x"}, cfg.Args)
	require.False(t, cfg.Writable)
	require.NotNil(t, cfg.ServeFrontend)
	require.True(t, *cfg.ServeFrontend)

	_, err = parseConfig([]byte(`{`))
	require.Error(t, err)
	_, err = parseConfig([]byte(`{"command":""}`))
	require.Error(t, err)
}

func TestParseConfigBasicAuth(t *testing.T) {
	cfg, err := parseConfig(nil)
	require.NoError(t, err)
	require.Nil(t, cfg.BasicAuth) // auth off by default

	cfg, err = parseConfig([]byte(`{"basic_auth":{"htpasswd":{"inline":"a:b"}}}`))
	require.NoError(t, err)
	require.NotNil(t, cfg.BasicAuth)
	require.Equal(t, defaultRealm, cfg.BasicAuth.Realm)

	cfg, err = parseConfig([]byte(`{"basic_auth":{"htpasswd":{"file":"/x"},"realm":"ops"}}`))
	require.NoError(t, err)
	require.Equal(t, "ops", cfg.BasicAuth.Realm)

	// A plain users map works without htpasswd, and both can be combined.
	cfg, err = parseConfig([]byte(`{"basic_auth":{"users":{"admin":"secret"}}}`))
	require.NoError(t, err)
	require.Equal(t, map[string]string{"admin": "secret"}, cfg.BasicAuth.Users)
	_, err = parseConfig([]byte(`{"basic_auth":{"htpasswd":{"file":"/x"},"users":{"admin":"secret"}}}`))
	require.NoError(t, err)

	// At least one of htpasswd/users is required, and htpasswd must set
	// exactly one of inline/file.
	_, err = parseConfig([]byte(`{"basic_auth":{}}`))
	require.Error(t, err)
	_, err = parseConfig([]byte(`{"basic_auth":{"htpasswd":{}}}`))
	require.Error(t, err)
	_, err = parseConfig([]byte(`{"basic_auth":{"htpasswd":{"inline":"a:b","file":"/x"}}}`))
	require.Error(t, err)

	// The realm is embedded in a quoted header value.
	_, err = parseConfig([]byte(`{"basic_auth":{"htpasswd":{"inline":"a:b"},"realm":"o\"ps"}}`))
	require.Error(t, err)
	_, err = parseConfig([]byte(`{"basic_auth":{"htpasswd":{"inline":"a:b"},"realm":"o\\ps"}}`))
	require.Error(t, err)
}

func TestAuthRequiredAllEndpoints(t *testing.T) {
	auth := testAuthenticator(t, "admin:"+minCostHash(t, "secret"))
	endpoints := []struct{ method, path string }{
		{"GET", "/"},
		{"GET", "/index.html"},
		{"GET", "/stream?sid=a"},
		{"POST", "/input?sid=a"},
		{"POST", "/resize?sid=a"},
		{"GET", "/nope"},
	}
	for _, creds := range []string{"", basicHeader("admin:wrong"), basicHeader("nobody:secret"), "Bearer tok"} {
		for _, ep := range endpoints {
			t.Run(ep.method+" "+ep.path+" creds="+creds, func(t *testing.T) {
				ctrl := gomock.NewController(t)
				h := newHandle(ctrl)
				var headers [][2]string
				h.EXPECT().SendLocalResponse(uint32(401), gomock.Any(), gomock.Any(), "web_terminal_unauthorized").
					Do(func(_ uint32, hs [][2]string, _ []byte, _ string) { headers = hs })

				f := &terminalFilter{cfg: &terminalConfig{Command: "cat", Writable: true}, handle: h, reg: newRegistry(), auth: auth}
				require.Equal(t, shared.HeadersStatusStopAllAndBuffer,
					f.OnRequestHeaders(headerMapWithAuth(ep.method, ep.path, creds), true))
				require.Contains(t, headers, [2]string{"www-authenticate", `Basic realm="web-terminal", charset="UTF-8"`})
			})
		}
	}
}

func TestAuthRejectedInputNeverReachesPTY(t *testing.T) {
	ctrl := gomock.NewController(t)
	h := newHandle(ctrl)
	h.EXPECT().SendLocalResponse(uint32(401), gomock.Any(), gomock.Any(), "web_terminal_unauthorized")

	f := &terminalFilter{
		cfg: &terminalConfig{Command: "cat", Writable: true}, handle: h, reg: newRegistry(),
		auth: testAuthenticator(t, "admin:"+minCostHash(t, "secret")),
	}
	require.Equal(t, shared.HeadersStatusStopAllAndBuffer,
		f.OnRequestHeaders(headerMapWithAuth("POST", "/input?sid=a", ""), false))
	// The 401 left act unset, so a straggling body is passed through untouched.
	require.Equal(t, actionNone, f.act)
	require.Equal(t, shared.BodyStatusContinue, f.OnRequestBody(fake.NewFakeBodyBuffer([]byte("x")), true))
}

func TestAuthSuccessReachesRouting(t *testing.T) {
	ctrl := gomock.NewController(t)
	h := newHandle(ctrl)
	h.EXPECT().SendLocalResponse(uint32(404), gomock.Any(), gomock.Any(), "web_terminal_frontend_disabled")

	f := &terminalFilter{
		cfg: &terminalConfig{Command: "cat", Writable: true, ServeFrontend: new(false)}, handle: h,
		reg: newRegistry(), auth: testAuthenticator(t, "admin:"+minCostHash(t, "secret")),
	}
	require.Equal(t, shared.HeadersStatusStopAllAndBuffer,
		f.OnRequestHeaders(headerMapWithAuth("GET", "/", basicHeader("admin:secret")), true))
}

func TestFrontendServedWhenEnabled(t *testing.T) {
	ctrl := gomock.NewController(t)
	h := newHandle(ctrl)
	var body []byte
	h.EXPECT().SendResponseHeaders(gomock.Any(), false)
	h.EXPECT().SendResponseData(gomock.Any(), true).Do(func(b []byte, _ bool) { body = b })

	f := &terminalFilter{cfg: &terminalConfig{Command: "cat", Writable: true, ServeFrontend: new(true)}, handle: h, reg: newRegistry()}
	require.Equal(t, shared.HeadersStatusStopAllAndBuffer, f.OnRequestHeaders(headerMap("GET", "/"), true))
	require.Contains(t, string(body), "xterm")
}

func TestFrontendServedByDefault(t *testing.T) {
	ctrl := gomock.NewController(t)
	h := newHandle(ctrl)
	h.EXPECT().SendResponseHeaders(gomock.Any(), false)
	h.EXPECT().SendResponseData(gomock.Any(), true)

	f := &terminalFilter{cfg: &terminalConfig{Command: "cat", Writable: true}, handle: h, reg: newRegistry()}
	require.Equal(t, shared.HeadersStatusStopAllAndBuffer, f.OnRequestHeaders(headerMap("GET", "/"), true))
}

func TestFrontendDisabled(t *testing.T) {
	ctrl := gomock.NewController(t)
	h := newHandle(ctrl)
	h.EXPECT().SendLocalResponse(uint32(404), gomock.Any(), gomock.Any(), "web_terminal_frontend_disabled")

	f := &terminalFilter{cfg: &terminalConfig{Command: "cat", Writable: true, ServeFrontend: new(false)}, handle: h, reg: newRegistry()}
	require.Equal(t, shared.HeadersStatusStopAllAndBuffer, f.OnRequestHeaders(headerMap("GET", "/"), true))
}

func TestFrontendWrongMethod(t *testing.T) {
	ctrl := gomock.NewController(t)
	h := newHandle(ctrl)
	h.EXPECT().SendLocalResponse(uint32(405), gomock.Any(), gomock.Any(), "web_terminal_method")

	f := &terminalFilter{cfg: &terminalConfig{Command: "cat", Writable: true, ServeFrontend: new(bool)}, handle: h, reg: newRegistry()}
	*f.cfg.ServeFrontend = true
	require.Equal(t, shared.HeadersStatusStopAllAndBuffer, f.OnRequestHeaders(headerMap("POST", "/"), true))
}

func TestRoutingErrors(t *testing.T) {
	tests := []struct {
		name       string
		method     string
		path       string
		wantStatus uint32
	}{
		{"unknown path", "GET", "/nope", 404},
		{"stream wrong method", "POST", "/stream?sid=a", 405},
		{"stream missing sid", "GET", "/stream", 400},
		{"input wrong method", "GET", "/input?sid=a", 405},
		{"resize unknown session", "POST", "/resize?sid=ghost", 404},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			h := newHandle(ctrl)
			h.EXPECT().SendLocalResponse(tt.wantStatus, gomock.Any(), gomock.Any(), gomock.Any())
			f := &terminalFilter{cfg: &terminalConfig{Command: "cat", Writable: true}, handle: h, reg: newRegistry()}
			require.Equal(t, shared.HeadersStatusStopAllAndBuffer, f.OnRequestHeaders(headerMap(tt.method, tt.path), true))
		})
	}
}

func TestStreamOutputAndExit(t *testing.T) {
	ctrl := gomock.NewController(t)
	h := newHandle(ctrl)
	frames := make(chan frame, 128)
	h.EXPECT().GetScheduler().Return(syncScheduler{}).AnyTimes()
	h.EXPECT().SendResponseHeaders(gomock.Any(), false).AnyTimes()
	h.EXPECT().SendResponseData(gomock.Any(), gomock.Any()).Do(func(b []byte, end bool) {
		cp := make([]byte, len(b))
		copy(cp, b)
		frames <- frame{cp, end}
	}).AnyTimes()

	f := (&filterFactory{cfg: &terminalConfig{Command: "sh", Args: []string{"-c", "printf hello-world"}, Writable: true}, reg: newRegistry()}).
		Create(h).(*terminalFilter)
	require.Equal(t, shared.HeadersStatusStopAllAndBuffer,
		f.OnRequestHeaders(headerMap("GET", "/stream?sid=s1&cols=80&rows=24"), true))

	var sawOutput, sawExit bool
	deadline := time.After(5 * time.Second)
	for !sawOutput || !sawExit {
		select {
		case fr := <-frames:
			if fr.end {
				sawExit = true
			} else if strings.Contains(decodeSSE(fr.data), "hello-world") {
				sawOutput = true
			}
		case <-deadline:
			t.Fatalf("output=%v exit=%v", sawOutput, sawExit)
		}
	}
	f.OnStreamComplete()
}

func TestStreamInputEcho(t *testing.T) {
	ctrl := gomock.NewController(t)
	factory := &filterFactory{cfg: &terminalConfig{Command: "cat", Writable: true}, reg: newRegistry()}

	streamH := newHandle(ctrl)
	frames := make(chan frame, 128)
	streamH.EXPECT().GetScheduler().Return(syncScheduler{}).AnyTimes()
	streamH.EXPECT().SendResponseHeaders(gomock.Any(), false).AnyTimes()
	streamH.EXPECT().SendResponseData(gomock.Any(), gomock.Any()).Do(func(b []byte, end bool) {
		cp := make([]byte, len(b))
		copy(cp, b)
		frames <- frame{cp, end}
	}).AnyTimes()
	streamF := factory.Create(streamH).(*terminalFilter)
	require.Equal(t, shared.HeadersStatusStopAllAndBuffer,
		streamF.OnRequestHeaders(headerMap("GET", "/stream?sid=s1&cols=80&rows=24"), true))

	inputH := newHandle(ctrl)
	inputH.EXPECT().SendLocalResponse(uint32(204), gomock.Any(), gomock.Any(), gomock.Any())
	inputF := factory.Create(inputH).(*terminalFilter)
	require.Equal(t, shared.HeadersStatusStop,
		inputF.OnRequestHeaders(headerMap("POST", "/input?sid=s1"), false))
	require.Equal(t, shared.BodyStatusStopAndBuffer,
		inputF.OnRequestBody(fake.NewFakeBodyBuffer([]byte("echoed-input\n")), true))

	deadline := time.After(5 * time.Second)
	for {
		select {
		case fr := <-frames:
			if !fr.end && strings.Contains(decodeSSE(fr.data), "echoed-input") {
				streamF.OnStreamComplete()
				time.Sleep(100 * time.Millisecond)
				return
			}
		case <-deadline:
			t.Fatal("did not observe echoed input on the stream")
		}
	}
}

func TestInputUnknownSession(t *testing.T) {
	ctrl := gomock.NewController(t)
	h := newHandle(ctrl)
	h.EXPECT().SendLocalResponse(uint32(404), gomock.Any(), gomock.Any(), gomock.Any())
	f := &terminalFilter{cfg: &terminalConfig{Command: "cat", Writable: true}, handle: h, reg: newRegistry()}
	require.Equal(t, shared.HeadersStatusStop, f.OnRequestHeaders(headerMap("POST", "/input?sid=ghost"), false))
	require.Equal(t, shared.BodyStatusStopAndBuffer, f.OnRequestBody(fake.NewFakeBodyBuffer([]byte("x")), true))
}

func TestResizeExistingSession(t *testing.T) {
	ctrl := gomock.NewController(t)
	factory := &filterFactory{cfg: &terminalConfig{Command: "cat", Writable: true}, reg: newRegistry()}

	streamH := newHandle(ctrl)
	streamH.EXPECT().GetScheduler().Return(syncScheduler{}).AnyTimes()
	streamH.EXPECT().SendResponseHeaders(gomock.Any(), false).AnyTimes()
	streamH.EXPECT().SendResponseData(gomock.Any(), gomock.Any()).AnyTimes()
	streamF := factory.Create(streamH).(*terminalFilter)
	streamF.OnRequestHeaders(headerMap("GET", "/stream?sid=s1&cols=80&rows=24"), true)
	t.Cleanup(streamF.OnStreamComplete)

	resizeH := newHandle(ctrl)
	resizeH.EXPECT().SendLocalResponse(uint32(204), gomock.Any(), gomock.Any(), gomock.Any())
	resizeF := factory.Create(resizeH).(*terminalFilter)
	require.Equal(t, shared.HeadersStatusStopAllAndBuffer,
		resizeF.OnRequestHeaders(headerMap("POST", "/resize?sid=s1&cols=120&rows=40"), true))
}

func TestInputEmptyBodyAcknowledged(t *testing.T) {
	ctrl := gomock.NewController(t)
	h := newHandle(ctrl)
	h.EXPECT().SendLocalResponse(uint32(204), gomock.Any(), gomock.Any(), gomock.Any())
	f := &terminalFilter{cfg: &terminalConfig{Command: "cat", Writable: true}, handle: h, reg: newRegistry()}
	require.Equal(t, shared.HeadersStatusStopAllAndBuffer,
		f.OnRequestHeaders(headerMap("POST", "/input?sid=s1"), true))
}

func TestConfigFactory(t *testing.T) {
	ctrl := gomock.NewController(t)
	h := mocks.NewMockHttpFilterConfigHandle(ctrl)
	h.EXPECT().Log(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()

	factory := &configFactory{}
	ff, err := factory.Create(h, []byte(`{"command":"cat"}`))
	require.NoError(t, err)
	require.NotNil(t, ff)

	_, err = factory.Create(h, []byte(`{"command":""}`))
	require.Error(t, err)

	// Valid basic_auth builds an authenticator; bad htpasswd data fails config load.
	ff, err = factory.Create(h, []byte(`{"command":"cat","basic_auth":{"htpasswd":{"inline":"admin:`+bcryptVector+`"}}}`))
	require.NoError(t, err)
	require.NotNil(t, ff.(*filterFactory).auth)
	_, err = factory.Create(h, []byte(`{"command":"cat","basic_auth":{"htpasswd":{"inline":"just-garbage"}}}`))
	require.Error(t, err)
	_, err = factory.Create(h, []byte(`{"command":"cat","basic_auth":{"htpasswd":{"file":"/does/not/exist"}}}`))
	require.Error(t, err)
	ff, err = factory.Create(h, []byte(`{"command":"cat","basic_auth":{"users":{"admin":"secret"}}}`))
	require.NoError(t, err)
	require.NotNil(t, ff.(*filterFactory).auth)

	perRoute, err := factory.CreatePerRoute([]byte(`{}`))
	require.NoError(t, err)
	require.Nil(t, perRoute)
}

func TestWellKnownHttpFilterConfigFactories(t *testing.T) {
	factories := WellKnownHttpFilterConfigFactories()
	require.Len(t, factories, 1)
	require.Contains(t, factories, "web-terminal")
}

func TestParseDim(t *testing.T) {
	require.Equal(t, uint16(24), parseDim("", 24))
	require.Equal(t, uint16(24), parseDim("bogus", 24))
	require.Equal(t, uint16(120), parseDim("120", 24))
}

func decodeSSE(frame []byte) string {
	s := strings.TrimSpace(strings.TrimPrefix(string(frame), "data: "))
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return ""
	}
	return string(b)
}
