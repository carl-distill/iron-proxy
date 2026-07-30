package secrets

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	githubAPIBaseURL       = "https://api.github.com"
	githubAPIVersion       = "2026-03-10"
	githubAppRefreshBefore = 5 * time.Minute
	githubMaxRepositories  = 500
	githubMaxResponseBytes = 1 << 20
)

var defaultGitHubAppClient = &http.Client{
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

type githubAppConfig struct {
	Type           string            `yaml:"type"`
	AppID          yaml.Node         `yaml:"app_id"`
	InstallationID yaml.Node         `yaml:"installation_id"`
	PrivateKey     yaml.Node         `yaml:"private_key"`
	Repositories   []string          `yaml:"repositories,omitempty"`
	Permissions    map[string]string `yaml:"permissions,omitempty"`
	FailureTTL     string            `yaml:"failure_ttl,omitempty"`
}

type nestedSourceBuilder func(yaml.Node) (secretSource, error)

type githubAppBuilder struct {
	logger      *slog.Logger
	buildSource nestedSourceBuilder
	client      *http.Client
	baseURL     string
	now         func() time.Time
}

func newGitHubAppBuilder(logger *slog.Logger, buildSource nestedSourceBuilder) *githubAppBuilder {
	return &githubAppBuilder{
		logger:      logger,
		buildSource: buildSource,
		client:      defaultGitHubAppClient,
		baseURL:     githubAPIBaseURL,
		now:         time.Now,
	}
}

func (b *githubAppBuilder) Build(raw yaml.Node) (secretSource, error) {
	var cfg githubAppConfig
	if err := raw.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parsing github_app source config: %w", err)
	}
	if len(cfg.Repositories) > githubMaxRepositories {
		return nil, fmt.Errorf("github_app source supports at most %d repositories", githubMaxRepositories)
	}
	failureTTL, err := parseTTL(cfg.FailureTTL)
	if err != nil {
		return nil, fmt.Errorf("parsing failure_ttl %q: %w", cfg.FailureTTL, err)
	}
	if failureTTL == 0 {
		failureTTL = defaultFailureTTL
	}

	appID, err := b.buildCredentialSource("app_id", cfg.AppID)
	if err != nil {
		return nil, err
	}
	installationID, err := b.buildCredentialSource("installation_id", cfg.InstallationID)
	if err != nil {
		return nil, err
	}
	privateKey, err := b.buildCredentialSource("private_key", cfg.PrivateKey)
	if err != nil {
		return nil, err
	}

	return &githubAppSource{
		name:           "github_app:" + installationID.Name(),
		appID:          appID,
		installationID: installationID,
		privateKey:     privateKey,
		repositories:   append([]string(nil), cfg.Repositories...),
		permissions:    cloneStringMap(cfg.Permissions),
		failureTTL:     failureTTL,
		logger:         b.logger,
		client:         b.client,
		baseURL:        strings.TrimRight(b.baseURL, "/"),
		now:            b.now,
	}, nil
}

func (b *githubAppBuilder) buildCredentialSource(field string, node yaml.Node) (secretSource, error) {
	if node.Kind == 0 {
		return nil, fmt.Errorf("github_app source requires %q field", field)
	}
	var hint sourceTypeHint
	if err := node.Decode(&hint); err != nil {
		return nil, fmt.Errorf("github_app %s: parsing source type: %w", field, err)
	}
	if hint.Type == "github_app" {
		return nil, fmt.Errorf("github_app %s cannot use another github_app source", field)
	}
	source, err := b.buildSource(node)
	if err != nil {
		return nil, fmt.Errorf("github_app %s: %w", field, err)
	}
	return source, nil
}

type githubAppSource struct {
	mu sync.Mutex

	name           string
	appID          secretSource
	installationID secretSource
	privateKey     secretSource
	repositories   []string
	permissions    map[string]string
	failureTTL     time.Duration
	logger         *slog.Logger
	client         *http.Client
	baseURL        string
	now            func() time.Time

	fingerprint [32]byte
	token       string
	expiresAt   time.Time
	lastErr     error
	retryAt     time.Time
	serveStale  bool
}

func (s *githubAppSource) Name() string { return s.name }

func (s *githubAppSource) Get(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	if s.lastErr != nil && now.Before(s.retryAt) {
		if s.serveStale && s.token != "" && now.Before(s.expiresAt) {
			return s.token, nil
		}
		return "", s.lastErr
	}

	fetchCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), fetchTimeout)
	defer cancel()

	credentials, fingerprint, err := s.resolveCredentials(fetchCtx)
	if err != nil {
		return "", err
	}
	if fingerprint == s.fingerprint && s.token != "" && now.Add(githubAppRefreshBefore).Before(s.expiresAt) {
		return s.token, nil
	}

	token, expiresAt, err := s.mint(fetchCtx, credentials, now)
	if err != nil {
		s.lastErr = err
		s.retryAt = now.Add(s.failureTTL)
		s.serveStale = fingerprint == s.fingerprint && s.token != "" && now.Before(s.expiresAt)
		if s.serveStale {
			if s.logger != nil {
				s.logger.Warn("failed to refresh GitHub App token, serving unexpired token",
					"secret", s.name,
					"error", err,
					"retry_in", s.failureTTL,
				)
			}
			return s.token, nil
		}
		if s.logger != nil {
			s.logger.Warn("failed to mint GitHub App token, caching error",
				"secret", s.name,
				"error", err,
				"retry_in", s.failureTTL,
			)
		}
		return "", err
	}

	s.fingerprint = fingerprint
	s.token = token
	s.expiresAt = expiresAt
	s.lastErr = nil
	s.retryAt = time.Time{}
	s.serveStale = false
	return token, nil
}

type githubAppCredentials struct {
	appID          string
	installationID int64
	privateKey     string
}

func (s *githubAppSource) resolveCredentials(ctx context.Context) (githubAppCredentials, [32]byte, error) {
	appID, err := s.appID.Get(ctx)
	if err != nil {
		return githubAppCredentials{}, [32]byte{}, fmt.Errorf("loading GitHub App ID from %q: %w", s.appID.Name(), err)
	}
	appID = strings.TrimSpace(appID)
	if appID == "" {
		return githubAppCredentials{}, [32]byte{}, fmt.Errorf("GitHub App ID from %q is empty", s.appID.Name())
	}

	installationIDValue, err := s.installationID.Get(ctx)
	if err != nil {
		return githubAppCredentials{}, [32]byte{}, fmt.Errorf("loading GitHub App installation ID from %q: %w", s.installationID.Name(), err)
	}
	installationID, err := strconv.ParseInt(strings.TrimSpace(installationIDValue), 10, 64)
	if err != nil || installationID <= 0 {
		return githubAppCredentials{}, [32]byte{}, fmt.Errorf("GitHub App installation ID from %q must be a positive integer", s.installationID.Name())
	}

	privateKey, err := s.privateKey.Get(ctx)
	if err != nil {
		return githubAppCredentials{}, [32]byte{}, fmt.Errorf("loading GitHub App private key from %q: %w", s.privateKey.Name(), err)
	}
	if privateKey == "" {
		return githubAppCredentials{}, [32]byte{}, fmt.Errorf("GitHub App private key from %q is empty", s.privateKey.Name())
	}

	credentials := githubAppCredentials{
		appID:          appID,
		installationID: installationID,
		privateKey:     privateKey,
	}
	return credentials, s.credentialsFingerprint(credentials), nil
}

func (s *githubAppSource) credentialsFingerprint(credentials githubAppCredentials) [32]byte {
	h := sha256.New()
	writeHashField(h, credentials.appID)
	writeHashField(h, strconv.FormatInt(credentials.installationID, 10))
	writeHashField(h, credentials.privateKey)
	for _, repository := range s.repositories {
		writeHashField(h, repository)
	}
	permissionNames := make([]string, 0, len(s.permissions))
	for name := range s.permissions {
		permissionNames = append(permissionNames, name)
	}
	sort.Strings(permissionNames)
	for _, name := range permissionNames {
		writeHashField(h, name)
		writeHashField(h, s.permissions[name])
	}
	var fingerprint [32]byte
	copy(fingerprint[:], h.Sum(nil))
	return fingerprint
}

func writeHashField(h io.Writer, value string) {
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(value)))
	// Hash writers never return write errors.
	_, _ = h.Write(size[:])
	_, _ = h.Write([]byte(value))
}

func (s *githubAppSource) mint(ctx context.Context, credentials githubAppCredentials, now time.Time) (string, time.Time, error) {
	privateKey, err := parseRSAPrivateKey([]byte(credentials.privateKey))
	if err != nil {
		return "", time.Time{}, err
	}
	jwt, err := signGitHubAppJWT(privateKey, credentials.appID, now)
	if err != nil {
		return "", time.Time{}, err
	}

	payload, err := json.Marshal(struct {
		Repositories []string          `json:"repositories,omitempty"`
		Permissions  map[string]string `json:"permissions,omitempty"`
	}{
		Repositories: s.repositories,
		Permissions:  s.permissions,
	})
	if err != nil {
		return "", time.Time{}, fmt.Errorf("encoding GitHub App token request: %w", err)
	}
	endpoint := fmt.Sprintf("%s/app/installations/%d/access_tokens", s.baseURL, credentials.installationID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(string(payload)))
	if err != nil {
		return "", time.Time{}, fmt.Errorf("creating GitHub App token request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "iron-proxy")
	req.Header.Set("X-GitHub-Api-Version", githubAPIVersion)

	resp, err := s.client.Do(req)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("requesting GitHub App installation token: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, githubMaxResponseBytes))
		return "", time.Time{}, fmt.Errorf("GitHub App installation token endpoint returned %s", resp.Status)
	}

	var result struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, githubMaxResponseBytes)).Decode(&result); err != nil {
		return "", time.Time{}, fmt.Errorf("decoding GitHub App installation token response: %w", err)
	}
	if result.Token == "" {
		return "", time.Time{}, fmt.Errorf("GitHub App installation token response contained an empty token")
	}
	if !result.ExpiresAt.After(now) {
		return "", time.Time{}, fmt.Errorf("GitHub App installation token response contained an invalid expiration")
	}
	return result.Token, result.ExpiresAt, nil
}

func parseRSAPrivateKey(value []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(value)
	if block == nil {
		return nil, fmt.Errorf("GitHub App private key is not PEM encoded")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing GitHub App RSA private key: %w", err)
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("GitHub App private key is not an RSA key")
	}
	return key, nil
}

func signGitHubAppJWT(privateKey *rsa.PrivateKey, appID string, now time.Time) (string, error) {
	header, err := json.Marshal(struct {
		Algorithm string `json:"alg"`
		Type      string `json:"typ"`
	}{Algorithm: "RS256", Type: "JWT"})
	if err != nil {
		return "", fmt.Errorf("encoding GitHub App JWT header: %w", err)
	}
	claims, err := json.Marshal(struct {
		IssuedAt  int64  `json:"iat"`
		ExpiresAt int64  `json:"exp"`
		Issuer    string `json:"iss"`
	}{
		IssuedAt:  now.Add(-time.Minute).Unix(),
		ExpiresAt: now.Add(9 * time.Minute).Unix(),
		Issuer:    appID,
	})
	if err != nil {
		return "", fmt.Errorf("encoding GitHub App JWT claims: %w", err)
	}

	unsigned := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims)
	digest := sha256.Sum256([]byte(unsigned))
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("signing GitHub App JWT: %w", err)
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func cloneStringMap(input map[string]string) map[string]string {
	if input == nil {
		return nil
	}
	result := make(map[string]string, len(input))
	for key, value := range input {
		result[key] = value
	}
	return result
}
