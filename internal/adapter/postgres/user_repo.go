package postgres

import (
	"context"

	"github.com/google/uuid"

	"github.com/gos0001/goauth/internal/adapter/postgres/generated"
	"github.com/gos0001/goauth/internal/domain"
)

// CreateUserParams carries only what the caller decides; the database supplies
// id and timestamps. Identifiers arrive already normalised.
type CreateUserParams struct {
	// Event is written in the same transaction as the row, so a created user
	// and the announcement of it cannot disagree. Nil emits nothing.
	Event *domain.OutboxEvent

	Username           string
	Email              string
	PasswordHash       string
	IsAdmin            bool
	Status             domain.UserStatus
	MustChangePassword bool
}

func (a *Adapter) CreateUser(ctx context.Context, p CreateUserParams) (domain.User, error) {
	status := p.Status
	if status == "" {
		status = domain.StatusActive
	}

	arg := generated.CreateUserParams{
		Username:           text(p.Username),
		Email:              text(p.Email),
		PasswordHash:       p.PasswordHash,
		IsAdmin:            p.IsAdmin,
		Status:             string(status),
		MustChangePassword: p.MustChangePassword,
	}

	// A transaction even though this is one insert: the event has to land with
	// it or not at all.
	var out domain.User
	err := a.withTx(ctx, func(q *generated.Queries) error {
		row, err := q.CreateUser(ctx, arg)
		if err != nil {
			return MapError(err, domain.ErrUserAlreadyExists)
		}
		out = toDomainUser(row)

		ev := p.Event
		if ev != nil {
			// Filled here rather than by the caller: only now is the id known.
			filled := domain.NewUserEvent(ev.Event, out)
			ev = &filled
		}
		return a.insertEvent(ctx, q, ev)
	})
	if err != nil {
		return domain.User{}, err
	}
	return out, nil
}

func (a *Adapter) GetUserByID(ctx context.Context, id string) (domain.User, error) {
	parsed, err := uuid.Parse(id)
	if err != nil {
		// A malformed id can only mean "no such user"; do not leak a parse
		// error up as an internal failure.
		return domain.User{}, domain.ErrUserNotFound
	}

	row, err := a.q.GetUserByID(ctx, parsed)
	if err != nil {
		return domain.User{}, MapError(err, domain.ErrUserNotFound)
	}
	return toDomainUser(row), nil
}

func (a *Adapter) GetUserByUsername(ctx context.Context, username string) (domain.User, error) {
	row, err := a.q.GetUserByUsername(ctx, text(username))
	if err != nil {
		return domain.User{}, MapError(err, domain.ErrUserNotFound)
	}
	return toDomainUser(row), nil
}

func (a *Adapter) GetUserByEmail(ctx context.Context, email string) (domain.User, error) {
	row, err := a.q.GetUserByEmail(ctx, text(email))
	if err != nil {
		return domain.User{}, MapError(err, domain.ErrUserNotFound)
	}
	return toDomainUser(row), nil
}

// UpdateUserParams uses pointers so that "not supplied" and "set to the zero
// value" stay distinguishable; a nil field leaves the column untouched.
type UpdateUserParams struct {
	// Event is written in the same transaction as the update. Nil emits nothing.
	Event *domain.OutboxEvent

	ID       string
	Username *string
	Email    *string
	Status   *domain.UserStatus
	IsAdmin  *bool
}

func (a *Adapter) UpdateUser(ctx context.Context, p UpdateUserParams) (domain.User, error) {
	id, err := uuid.Parse(p.ID)
	if err != nil {
		return domain.User{}, domain.ErrUserNotFound
	}

	arg := generated.UpdateUserParams{ID: id, IsAdmin: boolIn(p.IsAdmin)}
	if p.Username != nil {
		arg.Username = text(*p.Username)
	}
	if p.Email != nil {
		arg.Email = text(*p.Email)
	}
	if p.Status != nil {
		arg.Status = text(string(*p.Status))
	}

	var out domain.User
	err = a.withTx(ctx, func(q *generated.Queries) error {
		row, err := q.UpdateUser(ctx, arg)
		if err != nil {
			return MapError(err, domain.ErrUserNotFound)
		}
		out = toDomainUser(row)
		return a.insertEvent(ctx, q, eventFor(p.Event, out))
	})
	if err != nil {
		return domain.User{}, err
	}
	return out, nil
}

// UpdateUserAndRevokeSessions applies the update and drops every session of the
// target in one transaction. Blocking a user whose sessions survive is not a
// block, so the two writes must not be observable apart.
func (a *Adapter) UpdateUserAndRevokeSessions(ctx context.Context, p UpdateUserParams) (domain.User, error) {
	id, err := uuid.Parse(p.ID)
	if err != nil {
		return domain.User{}, domain.ErrUserNotFound
	}

	arg := generated.UpdateUserParams{ID: id, IsAdmin: boolIn(p.IsAdmin)}
	if p.Username != nil {
		arg.Username = text(*p.Username)
	}
	if p.Email != nil {
		arg.Email = text(*p.Email)
	}
	if p.Status != nil {
		arg.Status = text(string(*p.Status))
	}

	var out domain.User
	err = a.withTx(ctx, func(q *generated.Queries) error {
		row, err := q.UpdateUser(ctx, arg)
		if err != nil {
			return MapError(err, domain.ErrUserNotFound)
		}
		if _, err := q.DeleteUserSessions(ctx, id); err != nil {
			return MapError(err, nil)
		}
		out = toDomainUser(row)
		return a.insertEvent(ctx, q, eventFor(p.Event, out))
	})
	if err != nil {
		return domain.User{}, err
	}
	return out, nil
}

func (a *Adapter) SetUserPassword(ctx context.Context, id, passwordHash string, mustChange bool) (domain.User, error) {
	parsed, err := uuid.Parse(id)
	if err != nil {
		return domain.User{}, domain.ErrUserNotFound
	}

	row, err := a.q.SetUserPassword(ctx, generated.SetUserPasswordParams{
		ID:                 parsed,
		PasswordHash:       passwordHash,
		MustChangePassword: mustChange,
	})
	if err != nil {
		return domain.User{}, MapError(err, domain.ErrUserNotFound)
	}
	return toDomainUser(row), nil
}

// SetPasswordAndRevokeSessions changes the password and invalidates every
// existing session. A password change that leaves old sessions alive does not
// evict whoever the change was meant to evict.
func (a *Adapter) SetPasswordAndRevokeSessions(ctx context.Context, id, passwordHash string, mustChange bool, ev *domain.OutboxEvent) (domain.User, error) {
	parsed, err := uuid.Parse(id)
	if err != nil {
		return domain.User{}, domain.ErrUserNotFound
	}

	var out domain.User
	err = a.withTx(ctx, func(q *generated.Queries) error {
		row, err := q.SetUserPassword(ctx, generated.SetUserPasswordParams{
			ID:                 parsed,
			PasswordHash:       passwordHash,
			MustChangePassword: mustChange,
		})
		if err != nil {
			return MapError(err, domain.ErrUserNotFound)
		}
		if _, err := q.DeleteUserSessions(ctx, parsed); err != nil {
			return MapError(err, nil)
		}
		out = toDomainUser(row)
		return a.insertEvent(ctx, q, eventFor(ev, out))
	})
	if err != nil {
		return domain.User{}, err
	}
	return out, nil
}

// SoftDeleteUser marks the row deleted, clears its identifiers, and revokes its
// sessions. The row itself stays so user_id values held by other services never
// dangle.
func (a *Adapter) SoftDeleteUser(ctx context.Context, id string, ev *domain.OutboxEvent) (domain.User, error) {
	parsed, err := uuid.Parse(id)
	if err != nil {
		return domain.User{}, domain.ErrUserNotFound
	}

	var out domain.User
	err = a.withTx(ctx, func(q *generated.Queries) error {
		row, err := q.SoftDeleteUser(ctx, parsed)
		if err != nil {
			return MapError(err, domain.ErrUserNotFound)
		}
		if _, err := q.DeleteUserSessions(ctx, parsed); err != nil {
			return MapError(err, nil)
		}
		out = toDomainUser(row)
		return a.insertEvent(ctx, q, eventFor(ev, out))
	})
	if err != nil {
		return domain.User{}, err
	}
	return out, nil
}

func (a *Adapter) TouchUserLogin(ctx context.Context, id string) error {
	parsed, err := uuid.Parse(id)
	if err != nil {
		return domain.ErrUserNotFound
	}
	return MapError(a.q.TouchUserLogin(ctx, parsed), domain.ErrUserNotFound)
}

func (a *Adapter) CountActiveAdmins(ctx context.Context) (int, error) {
	n, err := a.q.CountActiveAdmins(ctx)
	if err != nil {
		return 0, MapError(err, nil)
	}
	return int(n), nil
}

type ListUsersParams struct {
	Query  string
	Status domain.UserStatus
	Limit  int
	Offset int
}

func (a *Adapter) ListUsers(ctx context.Context, p ListUsersParams) ([]domain.User, error) {
	rows, err := a.q.ListUsers(ctx, generated.ListUsersParams{
		Status: text(string(p.Status)),
		Q:      text(p.Query),
		Lim:    int32(p.Limit),
		Off:    int32(p.Offset),
	})
	if err != nil {
		return nil, MapError(err, nil)
	}

	out := make([]domain.User, 0, len(rows))
	for _, row := range rows {
		out = append(out, toDomainUser(row))
	}
	return out, nil
}

func (a *Adapter) CountUsers(ctx context.Context, p ListUsersParams) (int, error) {
	n, err := a.q.CountUsers(ctx, generated.CountUsersParams{
		Status: text(string(p.Status)),
		Q:      text(p.Query),
	})
	if err != nil {
		return 0, MapError(err, nil)
	}
	return int(n), nil
}

// eventFor fills an event's payload from the row as it now stands, so a
// consumer always receives the post-change state rather than what the caller
// guessed it would be.
func eventFor(ev *domain.OutboxEvent, u domain.User) *domain.OutboxEvent {
	if ev == nil {
		return nil
	}
	filled := domain.NewUserEvent(ev.Event, u)
	return &filled
}

func toDomainUser(r generated.GaUser) domain.User {
	return domain.User{
		ID:                 uuidText(r.ID),
		Username:           textOut(r.Username),
		Email:              textOut(r.Email),
		PasswordHash:       r.PasswordHash,
		IsAdmin:            r.IsAdmin,
		Status:             domain.UserStatus(r.Status),
		MustChangePassword: r.MustChangePassword,
		LastLoginAt:        tsOutPtr(r.LastLoginAt),
		CreatedAt:          tsOut(r.CreatedAt),
		UpdatedAt:          tsOut(r.UpdatedAt),
	}
}
