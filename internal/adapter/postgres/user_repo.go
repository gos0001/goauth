package postgres

import (
	"context"

	"github.com/google/uuid"
	"github.com/gos0001/goauth/v2/internal/adapter/postgres/generated"
	"github.com/gos0001/goauth/v2/internal/domain"
	"github.com/jackc/pgx/v5/pgtype"
)

// CreateUserParams carries only what the caller decides; the database supplies
// id and timestamps. Identifiers arrive already normalised.
type CreateUserParams struct {
	// Event is written in the same transaction as the row, so a created user
	// and the announcement of it cannot disagree. Nil emits nothing.
	Event *domain.OutboxEvent

	Username     string
	Email        string
	PasswordHash string
	Role         string
	Status       domain.UserStatus

	// CreatedBy is the delegated owner; "" stores NULL, an unowned row.
	CreatedBy string
}

func (a *Adapter) CreateUser(ctx context.Context, p CreateUserParams) (domain.User, error) {
	status := p.Status
	if status == "" {
		status = domain.StatusActive
	}

	role := p.Role
	if role == "" {
		role = domain.RoleUser
	}

	createdBy, err := pgUUID(p.CreatedBy)
	if err != nil {
		// An unparseable owner id can only mean "no such user".
		return domain.User{}, domain.ErrUserNotFound
	}

	arg := generated.CreateUserParams{
		Username:     text(p.Username),
		Email:        text(p.Email),
		PasswordHash: p.PasswordHash,
		Role:         role,
		Status:       string(status),
		CreatedBy:    createdBy,
	}

	// A transaction even though this is one insert: the event has to land with
	// it or not at all.
	var out domain.User
	err = a.withTx(ctx, func(q *generated.Queries) error {
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
	Role     *string
}

func (a *Adapter) UpdateUser(ctx context.Context, p UpdateUserParams) (domain.User, error) {
	id, err := uuid.Parse(p.ID)
	if err != nil {
		return domain.User{}, domain.ErrUserNotFound
	}

	arg := generated.UpdateUserParams{ID: id, Role: textIn(p.Role)}
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

	arg := generated.UpdateUserParams{ID: id, Role: textIn(p.Role)}
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

func (a *Adapter) SetUserPassword(ctx context.Context, id, passwordHash string) (domain.User, error) {
	parsed, err := uuid.Parse(id)
	if err != nil {
		return domain.User{}, domain.ErrUserNotFound
	}

	row, err := a.q.SetUserPassword(ctx, generated.SetUserPasswordParams{
		ID:           parsed,
		PasswordHash: passwordHash,
	})
	if err != nil {
		return domain.User{}, MapError(err, domain.ErrUserNotFound)
	}
	return toDomainUser(row), nil
}

// SetPasswordAndRevokeSessions changes the password and invalidates every
// existing session. A password change that leaves old sessions alive does not
// evict whoever the change was meant to evict.
func (a *Adapter) SetPasswordAndRevokeSessions(ctx context.Context, id, passwordHash string, ev *domain.OutboxEvent) (domain.User, error) {
	parsed, err := uuid.Parse(id)
	if err != nil {
		return domain.User{}, domain.ErrUserNotFound
	}

	var out domain.User
	err = a.withTx(ctx, func(q *generated.Queries) error {
		row, err := q.SetUserPassword(ctx, generated.SetUserPasswordParams{
			ID:           parsed,
			PasswordHash: passwordHash,
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

func (a *Adapter) CountActiveSuperAdmins(ctx context.Context) (int, error) {
	n, err := a.q.CountActiveSuperAdmins(ctx)
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

	// MinRank and Owner are the delegated-visibility filters; nil disables
	// the filter, which is what mode "off" and superadmin callers send.
	MinRank *int32
	Owner   *string
}

func (a *Adapter) ListUsers(ctx context.Context, p ListUsersParams) ([]domain.User, error) {
	arg := generated.ListUsersParams{
		Status: text(string(p.Status)),
		Q:      text(p.Query),
		Lim:    int32(p.Limit),
		Off:    int32(p.Offset),
	}
	if p.MinRank != nil {
		arg.MinRank = pgtype.Int4{Int32: *p.MinRank, Valid: true}
	}
	if p.Owner != nil {
		owner, err := pgUUID(*p.Owner)
		if err != nil {
			return nil, domain.ErrUserNotFound
		}
		arg.Owner = owner
	}

	rows, err := a.q.ListUsers(ctx, arg)
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
	arg := generated.CountUsersParams{
		Status: text(string(p.Status)),
		Q:      text(p.Query),
	}
	if p.MinRank != nil {
		arg.MinRank = pgtype.Int4{Int32: *p.MinRank, Valid: true}
	}
	if p.Owner != nil {
		owner, err := pgUUID(*p.Owner)
		if err != nil {
			return 0, domain.ErrUserNotFound
		}
		arg.Owner = owner
	}

	n, err := a.q.CountUsers(ctx, arg)
	if err != nil {
		return 0, MapError(err, nil)
	}
	return int(n), nil
}

// UpdateUserOwner transfers or clears delegated ownership. owner "" stores
// NULL — an explicit unassign, which is why this is its own statement rather
// than another COALESCE column on UpdateUser. The outbox event lands in the
// same transaction, like every other user write.
func (a *Adapter) UpdateUserOwner(ctx context.Context, id, owner string, ev *domain.OutboxEvent) (domain.User, error) {
	parsed, err := uuid.Parse(id)
	if err != nil {
		return domain.User{}, domain.ErrUserNotFound
	}

	ownerID, err := pgUUID(owner)
	if err != nil {
		return domain.User{}, domain.ErrUserNotFound
	}

	var out domain.User
	err = a.withTx(ctx, func(q *generated.Queries) error {
		row, err := q.UpdateUserOwner(ctx, generated.UpdateUserOwnerParams{ID: parsed, CreatedBy: ownerID})
		if err != nil {
			return MapError(err, domain.ErrUserNotFound)
		}
		out = toDomainUser(row)
		return a.insertEvent(ctx, q, eventFor(ev, out))
	})
	if err != nil {
		return domain.User{}, err
	}
	return out, nil
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
		ID:           uuidText(r.ID),
		Username:     textOut(r.Username),
		Email:        textOut(r.Email),
		PasswordHash: r.PasswordHash,
		Role:         r.Role,
		Status:       domain.UserStatus(r.Status),
		LastLoginAt:  tsOutPtr(r.LastLoginAt),
		CreatedAt:    tsOut(r.CreatedAt),
		UpdatedAt:    tsOut(r.UpdatedAt),
		CreatedBy:    pgUUIDOut(r.CreatedBy),
	}
}
