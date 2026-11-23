// Copyright 2026 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package openfga

import (
	"database/sql"
	sqldriver "database/sql/driver"
	"fmt"
	"testing"

	"github.com/juju/tc"
	"github.com/mattn/go-sqlite3"
	"github.com/openfga/openfga/pkg/storage"

	"github.com/juju/juju/internal/database/driver"
	coretesting "github.com/juju/juju/internal/testing"
)

type errorsSuite struct {
	coretesting.BaseSuite
}

func TestErrorsSuite(t *testing.T) {
	tc.Run(t, &errorsSuite{})
}

func (s *errorsSuite) TestTranslateDqliteConstraint(c *tc.C) {
	err := driver.Error{Code: int(sqlite3.ErrConstraintPrimaryKey), Message: "duplicate key"}
	got := translateError(fmt.Errorf("writing store: %w", err))
	c.Check(got, tc.ErrorIs, storage.ErrCollision)
	c.Check(got, tc.ErrorIs, err)
}

func (s *errorsSuite) TestTranslateNoRows(c *tc.C) {
	c.Check(translateError(sql.ErrNoRows), tc.ErrorIs, storage.ErrNotFound)
}

func (s *errorsSuite) TestBusyClassification(c *tc.C) {
	for _, code := range []int{int(sqlite3.ErrLockedSharedCache), driver.ErrBusy, driver.ErrBusySnapshot} {
		c.Check(isBusy(fmt.Errorf("query: %w", driver.Error{Code: code})), tc.IsTrue)
	}
	c.Check(isBusy(driver.Error{Code: int(sqlite3.ErrConstraintPrimaryKey)}), tc.IsFalse)
	c.Check(isBusy(sqldriver.ErrBadConn), tc.IsFalse)
	c.Check(translateError(sqldriver.ErrBadConn), tc.ErrorIs, sqldriver.ErrBadConn)
}
