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

// PublicKeyImporter describes a service that is capable of fetching and
// providing public keys for a subject from a set of well known sources that
// don't need to be understood by this service.
type PublicKeyImporter interface {
	// FetchPublicKeysForSubject is responsible for gathering all of the
	// public keys available for a specified subject.
	// The following errors can be expected:
	// - [importererrors.NoResolver] when there is no import resolver for the
	//   subject schema.
	// - [importererrors.SubjectNotFound] when the resolver has reported that no
	//   subject exists.
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
	// AddPublicKeysForUser adds one or more SSH public keys for a user to the
	// controller.
	AddPublicKeysForUser(context.Context, user.UUID, []keymanager.PublicKey) error

	// EnsurePublicKeysForUser adds the given keys for a user, skipping keys that
	// already exist.
	EnsurePublicKeysForUser(context.Context, user.UUID, []keymanager.PublicKey) error

	// GetPublicKeysForUser returns all public keys for a user. If the user does
	// not exist, no error is returned.
	GetPublicKeysForUser(context.Context, user.UUID) ([]coressh.PublicKey, error)

	// GetAllUsersPublicKeys returns the public keys in the controller grouped by
	// user name. This is useful for building a view during controller migration.
	GetAllUsersPublicKeys(context.Context) (map[user.Name][]string, error)

	// DeletePublicKeysForUser removes keys identified by fingerprint, comment,
	// or public key data.
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

// AddPublicKeysForUser is responsible for adding public keys for a user to the
// controller. The following errors can be expected:
//   - [errors.NotValid] when the user uuid is not valid
//   - [github.com/juju/juju/domain/access/errors.UserNotFound] when the user does
//     not exist.
//   - [keyerrors.InvalidPublicKey] when a public key fails validation.
//   - [keyerrors.ReservedCommentViolation] when a key being added contains a
//     comment string that is reserved.
//   - [keyerrors.PublicKeyAlreadyExists] when a public key being added for a user
//     already exists.
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
// The following errors can be expected:
//   - [errors.NotValid] when the user uuid is not valid
//   - [github.com/juju/juju/domain/access/errors.UserNotFound] when the provided
//     user does not exist.
func (s *Service) DeleteKeysForUser(ctx context.Context, userUUID user.UUID, targets ...string) error {
	ctx, span := trace.Start(ctx, trace.NameFromFunc())
	defer span.End()
	if err := userUUID.Validate(); err != nil {
		return errors.Errorf("validating user uuid %q when deleting public keys: %w", userUUID, err)
	}
	return s.st.DeletePublicKeysForUser(ctx, userUUID, targets)
}

// GetAllUsersPublicKeys returns all active users' public keys grouped by user
// name. This is useful for building a view during controller migration.
func (s *Service) GetAllUsersPublicKeys(ctx context.Context) (map[user.Name][]string, error) {
	ctx, span := trace.Start(ctx, trace.NameFromFunc())
	defer span.End()
	return s.st.GetAllUsersPublicKeys(ctx)
}

// ImportPublicKeysForUser will import all of the public keys available for a
// given subject and add them to the specified Juju user. If the user already
// has one or more of the public keys being imported they will safely be skipped
// with no errors being returned.
// The following errors can be expected:
//   - [errors.NotValid] when the user uuid is not valid
//   - [github.com/juju/juju/domain/access/errors.UserNotFound] when the user does
//     not exist.
//   - [keyerrors.InvalidPublicKey] when a key being imported fails validation.
//   - [keyerrors.ReservedCommentViolation] when a key being added contains a
//     comment string that is reserved.
//   - [keyerrors.UnknownImportSource] when the source for the import operation is
//     unknown to the service.
//   - [keyerrors.ImportSubjectNotFound] when the source has indicated that the
//     subject for the import operation does not exist.
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

// ListPublicKeysForUser is responsible for returning the public SSH keys for
// the specified user. The following errors can be expected:
//   - [errors.NotValid] when the user uuid is not valid.
//   - [github.com/juju/juju/domain/access/errors.UserNotFound] when the provided
//     user does not exist.
func (s *Service) ListPublicKeysForUser(ctx context.Context, userUUID user.UUID) ([]coressh.PublicKey, error) {
	ctx, span := trace.Start(ctx, trace.NameFromFunc())
	defer span.End()
	if err := userUUID.Validate(); err != nil {
		return nil, errors.Errorf("validating user uuid %q when listing public keys: %w", userUUID, err)
	}
	return s.st.GetPublicKeysForUser(ctx, userUUID)
}
