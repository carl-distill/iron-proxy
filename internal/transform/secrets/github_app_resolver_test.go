package secrets

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/ironsh/iron-proxy/internal/hostmatch"
)

type githubAppTestSource struct {
	mu    sync.Mutex
	name  string
	value string
	err   error
}

type fixedSecretSourceBuilder struct {
	source secretSource
}

func (b *fixedSecretSourceBuilder) Build(yaml.Node) (secretSource, error) {
	return b.source, nil
}

func (s *githubAppTestSource) Name() string { return s.name }

func (s *githubAppTestSource) Get(context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.value, s.err
}

func (s *githubAppTestSource) set(value string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.value = value
}

func githubAppPrivateKey(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)
	value := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	return string(value)
}

func githubAppSourceNode(t *testing.T, overrides ...func(map[string]any)) yaml.Node {
	t.Helper()
	config := map[string]any{
		"type":            "github_app",
		"app_id":          map[string]string{"type": "env", "var": "APP_ID"},
		"installation_id": map[string]string{"type": "env", "var": "INSTALLATION_ID"},
		"private_key":     map[string]string{"type": "env", "var": "PRIVATE_KEY"},
		"repositories":    []string{"sol"},
		"permissions":     map[string]string{"contents": "write", "pull_requests": "write"},
	}
	for _, override := range overrides {
		override(config)
	}
	return yamlNode(t, config)
}

func buildGitHubAppTestSource(
	t *testing.T,
	server *httptest.Server,
	now func() time.Time,
	sources map[string]*githubAppTestSource,
	overrides ...func(map[string]any),
) *githubAppSource {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	builder := newGitHubAppBuilder(logger, func(node yaml.Node) (secretSource, error) {
		var cfg envConfig
		if err := node.Decode(&cfg); err != nil {
			return nil, err
		}
		source, ok := sources[cfg.Var]
		if !ok {
			return nil, fmt.Errorf("unknown test source %q", cfg.Var)
		}
		return source, nil
	})
	builder.client = server.Client()
	builder.baseURL = server.URL
	builder.now = now
	source, err := builder.Build(githubAppSourceNode(t, overrides...))
	require.NoError(t, err)
	result, ok := source.(*githubAppSource)
	require.True(t, ok)
	return result
}

type recordedGitHubTokenRequest struct {
	path       string
	method     string
	authorizer string
	body       struct {
		Repositories []string          `json:"repositories"`
		Permissions  map[string]string `json:"permissions"`
	}
}

func TestGitHubAppSource_CachesAndRebuildsAfterCredentialRotation(t *testing.T) {
	privateKeyPEM := githubAppPrivateKey(t)
	now := time.Date(2026, time.July, 30, 12, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	var requests []recordedGitHubTokenRequest

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var recorded recordedGitHubTokenRequest
		recorded.path = r.URL.Path
		recorded.method = r.Method
		recorded.authorizer = r.Header.Get("Authorization")
		if err := json.NewDecoder(r.Body).Decode(&recorded.body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		mu.Lock()
		requests = append(requests, recorded)
		call := len(requests)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		// The httptest response writer does not report encoding failures in this handler.
		_ = json.NewEncoder(w).Encode(map[string]any{
			"token":      fmt.Sprintf("installation-token-%d", call),
			"expires_at": time.Now().Add(time.Hour),
		})
	}))
	t.Cleanup(server.Close)

	appID := &githubAppTestSource{name: "app-id", value: "123"}
	source := buildGitHubAppTestSource(t, server, func() time.Time { return now }, map[string]*githubAppTestSource{
		"APP_ID":          appID,
		"INSTALLATION_ID": {name: "installation-id", value: "12345"},
		"PRIVATE_KEY":     {name: "private-key", value: privateKeyPEM},
	})

	token, err := source.Get(context.Background())
	require.NoError(t, err)
	require.Equal(t, "installation-token-1", token)
	token, err = source.Get(context.Background())
	require.NoError(t, err)
	require.Equal(t, "installation-token-1", token)

	mu.Lock()
	require.Len(t, requests, 1)
	first := requests[0]
	mu.Unlock()
	require.Equal(t, http.MethodPost, first.method)
	require.Equal(t, "/app/installations/12345/access_tokens", first.path)
	require.True(t, strings.HasPrefix(first.authorizer, "Bearer "))
	require.Equal(t, []string{"sol"}, first.body.Repositories)
	require.Equal(t, map[string]string{"contents": "write", "pull_requests": "write"}, first.body.Permissions)

	appID.set("124")
	token, err = source.Get(context.Background())
	require.NoError(t, err)
	require.Equal(t, "installation-token-2", token)
	mu.Lock()
	require.Len(t, requests, 2)
	mu.Unlock()
}

func TestGitHubAppSource_ConcurrentGetsShareOneMint(t *testing.T) {
	privateKeyPEM := githubAppPrivateKey(t)
	now := time.Date(2026, time.July, 30, 12, 0, 0, 0, time.UTC)
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusCreated)
		// The httptest response writer does not report encoding failures in this handler.
		_ = json.NewEncoder(w).Encode(map[string]any{"token": "shared-token", "expires_at": time.Now().Add(time.Hour)})
	}))
	t.Cleanup(server.Close)
	source := buildGitHubAppTestSource(t, server, func() time.Time { return now }, map[string]*githubAppTestSource{
		"APP_ID":          {name: "app-id", value: "123"},
		"INSTALLATION_ID": {name: "installation-id", value: "456"},
		"PRIVATE_KEY":     {name: "private-key", value: privateKeyPEM},
	})

	const workers = 20
	var wg sync.WaitGroup
	errors := make(chan error, workers)
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			token, err := source.Get(context.Background())
			if err == nil && token != "shared-token" {
				err = fmt.Errorf("unexpected token %q", token)
			}
			errors <- err
		}()
	}
	wg.Wait()
	close(errors)
	for err := range errors {
		require.NoError(t, err)
	}
	require.Equal(t, int64(1), calls.Load())
}

func TestGitHubAppSource_ReplacesBearerAndBasicProxyCredentials(t *testing.T) {
	privateKeyPEM := githubAppPrivateKey(t)
	now := time.Date(2026, time.July, 30, 12, 0, 0, 0, time.UTC)
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusCreated)
		// The httptest response writer does not report encoding failures in this handler.
		_ = json.NewEncoder(w).Encode(map[string]any{"token": "installation-token", "expires_at": time.Now().Add(time.Hour)})
	}))
	t.Cleanup(server.Close)
	source := buildGitHubAppTestSource(t, server, func() time.Time { return now }, map[string]*githubAppTestSource{
		"APP_ID":          {name: "app-id", value: "123"},
		"INSTALLATION_ID": {name: "installation-id", value: "456"},
		"PRIVATE_KEY":     {name: "private-key", value: privateKeyPEM},
	})
	transformer, err := newFromConfig(secretsConfig{Secrets: []secretEntry{{
		Source: yamlNode(t, map[string]string{"type": "github_app"}),
		Rules: []hostmatch.RuleConfig{
			{Host: "api.github.com"},
			{Host: "github.com"},
		},
		Replace: &replaceConfig{
			ProxyValue:   "proxy-github-token",
			MatchHeaders: []string{"Authorization"},
			Require:      true,
		},
	}}}, sourceBuilderRegistry{"github_app": &fixedSecretSourceBuilder{source: source}})
	require.NoError(t, err)

	apiRequest := httptest.NewRequest(http.MethodGet, "https://api.github.com/user", nil)
	apiRequest.Header.Set("Authorization", "Bearer proxy-github-token")
	doTransform(t, transformer, apiRequest)
	require.Equal(t, "Bearer installation-token", apiRequest.Header.Get("Authorization"))

	gitRequest := httptest.NewRequest(http.MethodGet, "https://github.com/Distill-Energy/sol.git/info/refs", nil)
	encodedCredentials := base64.StdEncoding.EncodeToString([]byte("x-access-token:proxy-github-token"))
	gitRequest.Header.Set("Authorization", "Basic "+encodedCredentials)
	doTransform(t, transformer, gitRequest)
	decodedCredentials, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(gitRequest.Header.Get("Authorization"), "Basic "))
	require.NoError(t, err)
	require.Equal(t, "x-access-token:installation-token", string(decodedCredentials))
	require.Equal(t, int64(1), calls.Load())
}

func TestGitHubAppSource_CachesFailuresWithoutLeakingResponseBody(t *testing.T) {
	privateKeyPEM := githubAppPrivateKey(t)
	now := time.Date(2026, time.July, 30, 12, 0, 0, 0, time.UTC)
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
		// The response deliberately contains a value that must not reach the resolver error.
		_, _ = w.Write([]byte(`{"token":"response-secret"}`))
	}))
	t.Cleanup(server.Close)
	appID := &githubAppTestSource{name: "app-id", value: "123"}
	source := buildGitHubAppTestSource(t, server, func() time.Time { return now }, map[string]*githubAppTestSource{
		"APP_ID":          appID,
		"INSTALLATION_ID": {name: "installation-id", value: "456"},
		"PRIVATE_KEY":     {name: "private-key", value: privateKeyPEM},
	})

	_, err := source.Get(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "401 Unauthorized")
	require.NotContains(t, err.Error(), "response-secret")
	_, err = source.Get(context.Background())
	require.Error(t, err)
	require.Equal(t, int64(1), calls.Load())

	appID.set("124")
	_, err = source.Get(context.Background())
	require.Error(t, err)
	require.Equal(t, int64(2), calls.Load())
}

func TestGitHubAppSource_RetriesEmptyTokenResponseAfterFailureTTL(t *testing.T) {
	privateKeyPEM := githubAppPrivateKey(t)
	now := time.Date(2026, time.July, 30, 12, 0, 0, 0, time.UTC)
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		call := calls.Add(1)
		token := ""
		if call > 1 {
			token = "recovered-token"
		}
		w.WriteHeader(http.StatusCreated)
		// The httptest response writer does not report encoding failures in this handler.
		_ = json.NewEncoder(w).Encode(map[string]any{"token": token, "expires_at": time.Now().Add(time.Hour)})
	}))
	t.Cleanup(server.Close)
	source := buildGitHubAppTestSource(t, server, func() time.Time { return now }, map[string]*githubAppTestSource{
		"APP_ID":          {name: "app-id", value: "123"},
		"INSTALLATION_ID": {name: "installation-id", value: "456"},
		"PRIVATE_KEY":     {name: "private-key", value: privateKeyPEM},
	})

	_, err := source.Get(context.Background())
	require.ErrorContains(t, err, "empty token")
	now = now.Add(defaultFailureTTL)
	token, err := source.Get(context.Background())
	require.NoError(t, err)
	require.Equal(t, "recovered-token", token)
	require.Equal(t, int64(2), calls.Load())
}

type githubAppRoundTripper func(*http.Request) (*http.Response, error)

func (fn githubAppRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}

type trackedGitHubResponseBody struct {
	io.Reader
	closed atomic.Bool
}

func (b *trackedGitHubResponseBody) Close() error {
	b.closed.Store(true)
	return nil
}

func TestGitHubAppSource_ClosesFailureResponseBody(t *testing.T) {
	privateKeyPEM := githubAppPrivateKey(t)
	now := time.Date(2026, time.July, 30, 12, 0, 0, 0, time.UTC)
	server := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(server.Close)
	source := buildGitHubAppTestSource(t, server, func() time.Time { return now }, map[string]*githubAppTestSource{
		"APP_ID":          {name: "app-id", value: "123"},
		"INSTALLATION_ID": {name: "installation-id", value: "456"},
		"PRIVATE_KEY":     {name: "private-key", value: privateKeyPEM},
	})
	body := &trackedGitHubResponseBody{Reader: strings.NewReader(`{"token":"response-secret"}`)}
	source.client = &http.Client{Transport: githubAppRoundTripper(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusUnauthorized,
			Status:     "401 Unauthorized",
			Header:     make(http.Header),
			Body:       body,
			Request:    req,
		}, nil
	})}

	_, err := source.Get(context.Background())
	require.Error(t, err)
	require.True(t, body.closed.Load())
	var httpErr *ghinstallation.HTTPError
	require.ErrorAs(t, err, &httpErr)
	require.Equal(t, http.NoBody, httpErr.Response.Body)
	require.Empty(t, httpErr.Response.Request.Header.Get("Authorization"))
}

func TestGitHubAppBuilder_ValidatesConfiguration(t *testing.T) {
	privateKeyPEM := githubAppPrivateKey(t)
	server := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(server.Close)
	sources := map[string]*githubAppTestSource{
		"APP_ID":          {name: "app-id", value: "123"},
		"INSTALLATION_ID": {name: "installation-id", value: "456"},
		"PRIVATE_KEY":     {name: "private-key", value: privateKeyPEM},
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	builder := newGitHubAppBuilder(logger, func(node yaml.Node) (secretSource, error) {
		var cfg envConfig
		require.NoError(t, node.Decode(&cfg))
		return sources[cfg.Var], nil
	})

	tests := []struct {
		name     string
		override func(map[string]any)
		errMsg   string
	}{
		{
			name: "missing app ID",
			override: func(config map[string]any) {
				delete(config, "app_id")
			},
			errMsg: `requires "app_id" field`,
		},
		{
			name: "missing installation ID",
			override: func(config map[string]any) {
				delete(config, "installation_id")
			},
			errMsg: `requires "installation_id" field`,
		},
		{
			name: "missing private key",
			override: func(config map[string]any) {
				delete(config, "private_key")
			},
			errMsg: `requires "private_key" field`,
		},
		{
			name: "invalid failure TTL",
			override: func(config map[string]any) {
				config["failure_ttl"] = "eventually"
			},
			errMsg: "parsing failure_ttl",
		},
		{
			name: "too many repositories",
			override: func(config map[string]any) {
				config["repositories"] = make([]string, githubMaxRepositories+1)
			},
			errMsg: "at most 500 repositories",
		},
		{
			name: "unknown permission",
			override: func(config map[string]any) {
				config["permissions"] = map[string]string{"future_permission": "read"}
			},
			errMsg: `unknown field "future_permission"`,
		},
		{
			name: "recursive source",
			override: func(config map[string]any) {
				config["app_id"] = map[string]any{"type": "github_app"}
			},
			errMsg: "cannot use another github_app source",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := builder.Build(githubAppSourceNode(t, tc.override))
			require.ErrorContains(t, err, tc.errMsg)
		})
	}
}

func TestDefaultRegistry_BuildsGitHubAppSource(t *testing.T) {
	t.Setenv("GITHUB_APP_ID", "123")
	t.Setenv("GITHUB_INSTALLATION_ID", "456")
	t.Setenv("GITHUB_PRIVATE_KEY", "deferred-until-get")
	node := yamlNode(t, map[string]any{
		"type":            "github_app",
		"app_id":          map[string]string{"type": "env", "var": "GITHUB_APP_ID"},
		"installation_id": map[string]string{"type": "env", "var": "GITHUB_INSTALLATION_ID"},
		"private_key":     map[string]string{"type": "env", "var": "GITHUB_PRIVATE_KEY"},
	})

	source, err := resolveSource(defaultRegistry(slog.Default()), node)
	require.NoError(t, err)
	require.IsType(t, &githubAppSource{}, source)
}

func TestGitHubAppSource_RejectsInvalidResolvedCredentials(t *testing.T) {
	privateKeyPEM := githubAppPrivateKey(t)
	now := time.Date(2026, time.July, 30, 12, 0, 0, 0, time.UTC)
	server := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(server.Close)

	tests := []struct {
		name    string
		appID   string
		install string
		key     string
		errMsg  string
	}{
		{name: "invalid app ID", appID: "Iv1.client-id", install: "456", key: privateKeyPEM, errMsg: "positive integer"},
		{name: "invalid installation ID", appID: "123", install: "not-an-id", key: privateKeyPEM, errMsg: "positive integer"},
		{name: "invalid private key", appID: "123", install: "456", key: "not-pem", errMsg: "PEM encoded"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			source := buildGitHubAppTestSource(t, server, func() time.Time { return now }, map[string]*githubAppTestSource{
				"APP_ID":          {name: "app-id", value: tc.appID},
				"INSTALLATION_ID": {name: "installation-id", value: tc.install},
				"PRIVATE_KEY":     {name: "private-key", value: tc.key},
			})
			_, err := source.Get(context.Background())
			require.ErrorContains(t, err, tc.errMsg)
		})
	}
}
