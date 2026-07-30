package secrets

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/google/go-github/v88/github"
	"gopkg.in/yaml.v3"
)

const (
	githubAPIBaseURL       = "https://api.github.com"
	githubMaxRepositories  = 500
	githubMaxResponseBytes = 1 << 20
)

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
		client:      http.DefaultClient,
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
	tokenOptions, err := githubInstallationTokenOptions(cfg.Repositories, cfg.Permissions)
	if err != nil {
		return nil, err
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
		tokenOptions:   tokenOptions,
		failureTTL:     failureTTL,
		logger:         b.logger,
		client:         b.client,
		baseURL:        strings.TrimRight(b.baseURL, "/"),
		now:            b.now,
	}, nil
}

func githubInstallationTokenOptions(
	repositories []string,
	permissionValues map[string]string,
) (*github.InstallationTokenOptions, error) {
	if len(repositories) == 0 && len(permissionValues) == 0 {
		return nil, nil
	}
	options := &github.InstallationTokenOptions{
		Repositories: append([]string(nil), repositories...),
	}
	if len(permissionValues) == 0 {
		return options, nil
	}

	// ghinstallation accepts go-github's typed permissions rather than the API's
	// string map. Reject unknown keys so a new or misspelled permission is not
	// silently omitted by encoding/json.
	encoded, err := json.Marshal(permissionValues)
	if err != nil {
		return nil, fmt.Errorf("encoding github_app permissions: %w", err)
	}
	var permissions github.InstallationPermissions
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&permissions); err != nil {
		return nil, fmt.Errorf("parsing github_app permissions: %w", err)
	}
	options.Permissions = &permissions
	return options, nil
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
	tokenOptions   *github.InstallationTokenOptions
	failureTTL     time.Duration
	logger         *slog.Logger
	client         *http.Client
	baseURL        string
	now            func() time.Time

	fingerprint [32]byte
	transport   *ghinstallation.Transport

	failedFingerprint [32]byte
	lastErr           error
	retryAt           time.Time
}

func (s *githubAppSource) Name() string { return s.name }

func (s *githubAppSource) Get(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	fetchCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), fetchTimeout)
	defer cancel()

	credentials, fingerprint, err := s.resolveCredentials(fetchCtx)
	if err != nil {
		return "", err
	}
	now := s.now()
	if s.lastErr != nil && fingerprint == s.failedFingerprint && now.Before(s.retryAt) {
		return "", s.lastErr
	}
	if s.transport == nil || fingerprint != s.fingerprint {
		transport, err := s.newTransport(credentials)
		if err != nil {
			return s.cacheFailure(fingerprint, err)
		}
		s.fingerprint = fingerprint
		s.transport = transport
	}

	token, err := s.transport.Token(fetchCtx)
	if err != nil {
		return s.cacheFailure(fingerprint, githubInstallationTokenError(err))
	}
	if token == "" {
		// ghinstallation caches the decoded response before returning the token.
		// Discard it so failure_ttl expiration can trigger a new request.
		s.transport = nil
		return s.cacheFailure(fingerprint, fmt.Errorf("GitHub App installation token response contained an empty token"))
	}

	s.failedFingerprint = [32]byte{}
	s.lastErr = nil
	s.retryAt = time.Time{}
	return token, nil
}

func (s *githubAppSource) newTransport(credentials githubAppCredentials) (*ghinstallation.Transport, error) {
	baseTransport := s.client.Transport
	if baseTransport == nil {
		baseTransport = http.DefaultTransport
	}
	transport, err := ghinstallation.New(
		baseTransport,
		credentials.appID,
		credentials.installationID,
		[]byte(credentials.privateKey),
	)
	if err != nil {
		return nil, fmt.Errorf("configuring GitHub App authentication: %w", err)
	}
	transport.BaseURL = s.baseURL
	transport.Client = s.client
	transport.InstallationTokenOptions = s.tokenOptions
	return transport, nil
}

func (s *githubAppSource) cacheFailure(fingerprint [32]byte, err error) (string, error) {
	s.failedFingerprint = fingerprint
	s.lastErr = err
	s.retryAt = s.now().Add(s.failureTTL)
	if s.logger != nil {
		s.logger.Warn("failed to mint GitHub App token, caching error",
			"secret", s.name,
			"error", err,
			"retry_in", s.failureTTL,
		)
	}
	return "", err
}

func githubInstallationTokenError(err error) error {
	// ghinstallation leaves non-2xx bodies open so callers can inspect them.
	// iron-proxy does not expose GitHub response bodies, so close the body and
	// scrub the generated JWT before this error is cached or logged.
	// https://github.com/bradleyfalzon/ghinstallation/blob/v2.19.0/transport.go#L241-L246
	var httpErr *ghinstallation.HTTPError
	if errors.As(err, &httpErr) && httpErr.Response != nil {
		if httpErr.Response.Body != nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(httpErr.Response.Body, githubMaxResponseBytes))
			_ = httpErr.Response.Body.Close()
			httpErr.Response.Body = http.NoBody
		}
		if httpErr.Response.Request != nil {
			httpErr.Response.Request.Header.Del("Authorization")
		}
	}
	return fmt.Errorf("requesting GitHub App installation token: %w", err)
}

type githubAppCredentials struct {
	appID          int64
	installationID int64
	privateKey     string
}

func (s *githubAppSource) resolveCredentials(ctx context.Context) (githubAppCredentials, [32]byte, error) {
	appID, err := s.appID.Get(ctx)
	if err != nil {
		return githubAppCredentials{}, [32]byte{}, fmt.Errorf("loading GitHub App ID from %q: %w", s.appID.Name(), err)
	}
	appIDValue, err := strconv.ParseInt(strings.TrimSpace(appID), 10, 64)
	if err != nil || appIDValue <= 0 {
		return githubAppCredentials{}, [32]byte{}, fmt.Errorf("GitHub App ID from %q must be a positive integer", s.appID.Name())
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
		appID:          appIDValue,
		installationID: installationID,
		privateKey:     privateKey,
	}
	return credentials, s.credentialsFingerprint(credentials), nil
}

func (s *githubAppSource) credentialsFingerprint(credentials githubAppCredentials) [32]byte {
	value := strconv.FormatInt(credentials.appID, 10) + "\x00" +
		strconv.FormatInt(credentials.installationID, 10) + "\x00" + credentials.privateKey
	return sha256.Sum256([]byte(value))
}
