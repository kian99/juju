// Copyright 2024 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package service

import (
	"context"
	"net/url"

	"github.com/juju/collections/set"

	coressh "github.com/juju/juju/core/ssh"
	"github.com/juju/juju/core/trace"
	"github.com/juju/juju/core/user"
	"github.com/juju/juju/domain/controller"
	"github.com/juju/juju/domain/keymanager"
	keyerrors "github.com/juju/juju/domain/keymanager/errors"
	"github.com/juju/juju/internal/errors"
	"github.com/juju/juju/internal/ssh"
	importererrors "github.com/juju/juju/internal/ssh/importer/errors"
)

// PublicKeyImporter fetches public keys from a well-known external source.
type PublicKeyImporter interface {
	FetchPublicKeysForSubject(context.Context, *url.URL) ([]string, error)
}

// Service provides controller-scoped user public SSH key management.
type Service struct {
	st State
}

// ImporterService extends Service with external key importing.
type ImporterService struct {
	*Service
	keyImporter PublicKeyImporter
}

// State provides controller-scoped persistence for user public SSH keys.
type State interface {
	AddPublicKeysForUser(context.Context, user.UUID, []keymanager.PublicKey) error
	EnsurePublicKeysForUser(context.Context, user.UUID, []keymanager.PublicKey) error
	GetPublicKeysForUser(context.Context, user.UUID) ([]coressh.PublicKey, error)
	GetAllUsersPublicKeys(context.Context) (map[user.Name][]string, error)
	DeletePublicKeysForUser(context.Context, user.UUID, []string) error
}

var reservedPublicKeyComments = set.NewStrings(controller.ControllerSSHKeyComment)

// NewService constructs a controller-scoped key manager service.
func NewService(state State) *Service {
	return &Service{st: state}
}

// NewImporterService constructs a controller-scoped importer service.
func NewImporterService(keyImporter PublicKeyImporter, state State) *ImporterService {
	return &ImporterService{
		Service:     NewService(state),
		keyImporter: keyImporter,
	}
}

// AddPublicKeysForUser adds public keys for a user to the controller.
func (s *Service) AddPublicKeysForUser(ctx context.Context, userUUID user.UUID, keys ...string) error {
	ctx, span := trace.Start(ctx, trace.NameFromFunc())
	defer span.End()

	if err := userUUID.Validate(); err != nil {
		return errors.Errorf("validating user uuid %q when adding public keys: %w", userUUID, err)
	}
	if len(keys) == 0 {
		return nil
	}

	toAdd := make([]keymanager.PublicKey, 0, len(keys))
	for i, keyToAdd := range keys {
		parsedKey, err := ssh.ParsePublicKey(keyToAdd)
		if err != nil {
			return errors.Errorf("%w %q at index %d: %w", keyerrors.InvalidPublicKey, keyToAdd, i, err)
		}
		if reservedPublicKeyComments.Contains(parsedKey.Comment) {
			return errors.Errorf("public key %q at index %d contains reserved comment %q", keyToAdd, i, parsedKey.Comment).
				Add(keyerrors.ReservedCommentViolation)
		}
		toAdd = append(toAdd, keymanager.PublicKey{
			Comment: parsedKey.Comment, FingerprintHash: keymanager.FingerprintHashAlgorithmSHA256,
			Fingerprint: parsedKey.Fingerprint(), Key: keyToAdd,
		})
	}
	return s.st.AddPublicKeysForUser(ctx, userUUID, toAdd)
}

// DeleteKeysForUser removes keys identified by fingerprint, comment, or value.
func (s *Service) DeleteKeysForUser(ctx context.Context, userUUID user.UUID, targets ...string) error {
	ctx, span := trace.Start(ctx, trace.NameFromFunc())
	defer span.End()
	if err := userUUID.Validate(); err != nil {
		return errors.Errorf("validating user uuid %q when deleting public keys: %w", userUUID, err)
	}
	return s.st.DeletePublicKeysForUser(ctx, userUUID, targets)
}

// GetAllUsersPublicKeys returns active users' public keys grouped by user.
func (s *Service) GetAllUsersPublicKeys(ctx context.Context) (map[user.Name][]string, error) {
	ctx, span := trace.Start(ctx, trace.NameFromFunc())
	defer span.End()
	return s.st.GetAllUsersPublicKeys(ctx)
}

// ImportPublicKeysForUser imports public keys from an external source.
func (s *ImporterService) ImportPublicKeysForUser(ctx context.Context, userUUID user.UUID, subject *url.URL) error {
	ctx, span := trace.Start(ctx, trace.NameFromFunc())
	defer span.End()
	if err := userUUID.Validate(); err != nil {
		return errors.Errorf("validating user uuid %q when importing public keys from %q: %w", userUUID, subject.String(), err)
	}

	keys, err := s.keyImporter.FetchPublicKeysForSubject(ctx, subject)
	switch {
	case errors.Is(err, importererrors.NoResolver):
		return errors.Errorf("importing public keys for user %q, unknown public key source %q", userUUID, subject.Scheme).Add(keyerrors.UnknownImportSource)
	case errors.Is(err, importererrors.SubjectNotFound):
		return errors.Errorf("importing public keys for user %q, import subject %q not found", userUUID, subject.String()).Add(keyerrors.ImportSubjectNotFound)
	case err != nil:
		return errors.Errorf("importing public keys for user %q using subject %q: %w", userUUID, subject.String(), err)
	}

	toAdd := make([]keymanager.PublicKey, 0, len(keys))
	for i, key := range keys {
		parsedKey, err := ssh.ParsePublicKey(key)
		if err != nil {
			return errors.Errorf("parsing key %d for subject %q when importing keys for user %q: %w", i, subject.String(), userUUID, err).Add(keyerrors.InvalidPublicKey)
		}
		if reservedPublicKeyComments.Contains(parsedKey.Comment) {
			return errors.Errorf("importing key %d for user %q because comment %q is reserved", i, userUUID, parsedKey.Comment).Add(keyerrors.ReservedCommentViolation)
		}
		toAdd = append(toAdd, keymanager.PublicKey{
			Comment: parsedKey.Comment, Key: key, FingerprintHash: keymanager.FingerprintHashAlgorithmSHA256,
			Fingerprint: parsedKey.Fingerprint(),
		})
	}
	return s.st.EnsurePublicKeysForUser(ctx, userUUID, toAdd)
}

// ListPublicKeysForUser returns all public keys for a user.
func (s *Service) ListPublicKeysForUser(ctx context.Context, userUUID user.UUID) ([]coressh.PublicKey, error) {
	ctx, span := trace.Start(ctx, trace.NameFromFunc())
	defer span.End()
	if err := userUUID.Validate(); err != nil {
		return nil, errors.Errorf("validating user uuid %q when listing public keys: %w", userUUID, err)
	}
	return s.st.GetPublicKeysForUser(ctx, userUUID)
}
