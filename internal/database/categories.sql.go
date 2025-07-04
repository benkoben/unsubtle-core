// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.29.0
// source: categories.sql

package database

import (
	"context"
	"database/sql"

	"github.com/google/uuid"
)

const checkExistingCategory = `-- name: CheckExistingCategory :one
SELECT id, created_at, updated_at, name, description, created_by FROM categories
WHERE name = $1 AND created_by = $2
`

type CheckExistingCategoryParams struct {
	Name      string    `json:"name"`
	CreatedBy uuid.UUID `json:"created_by"`
}

func (q *Queries) CheckExistingCategory(ctx context.Context, arg CheckExistingCategoryParams) (Category, error) {
	row := q.db.QueryRowContext(ctx, checkExistingCategory, arg.Name, arg.CreatedBy)
	var i Category
	err := row.Scan(
		&i.ID,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.Name,
		&i.Description,
		&i.CreatedBy,
	)
	return i, err
}

const createCategory = `-- name: CreateCategory :one
INSERT INTO categories (created_at, updated_at, name, description, created_by)
VALUES (
NOW(),
NOW(),
$1,
$2,
$3
)
RETURNING id, created_at, updated_at, name, description, created_by
`

type CreateCategoryParams struct {
	Name        string    `json:"name"`
	Description string    `json:"description"`
	CreatedBy   uuid.UUID `json:"created_by"`
}

func (q *Queries) CreateCategory(ctx context.Context, arg CreateCategoryParams) (Category, error) {
	row := q.db.QueryRowContext(ctx, createCategory, arg.Name, arg.Description, arg.CreatedBy)
	var i Category
	err := row.Scan(
		&i.ID,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.Name,
		&i.Description,
		&i.CreatedBy,
	)
	return i, err
}

const deleteCategory = `-- name: DeleteCategory :execresult
DELETE FROM categories
WHERE id = $1
`

func (q *Queries) DeleteCategory(ctx context.Context, id uuid.UUID) (sql.Result, error) {
	return q.db.ExecContext(ctx, deleteCategory, id)
}

const getCategory = `-- name: GetCategory :one
SELECT id, created_at, updated_at, name, description, created_by FROM categories
WHERE id = $1
`

func (q *Queries) GetCategory(ctx context.Context, id uuid.UUID) (Category, error) {
	row := q.db.QueryRowContext(ctx, getCategory, id)
	var i Category
	err := row.Scan(
		&i.ID,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.Name,
		&i.Description,
		&i.CreatedBy,
	)
	return i, err
}

const listCategories = `-- name: ListCategories :many
SELECT id, created_at, updated_at, name, description, created_by FROM categories
ORDER BY name ASC
`

func (q *Queries) ListCategories(ctx context.Context) ([]Category, error) {
	rows, err := q.db.QueryContext(ctx, listCategories)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []Category
	for rows.Next() {
		var i Category
		if err := rows.Scan(
			&i.ID,
			&i.CreatedAt,
			&i.UpdatedAt,
			&i.Name,
			&i.Description,
			&i.CreatedBy,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const listCategoriesForUserId = `-- name: ListCategoriesForUserId :many
SELECT id, created_at, updated_at, name, description, created_by FROM categories
WHERE created_by = $1
ORDER BY name ASC
`

func (q *Queries) ListCategoriesForUserId(ctx context.Context, createdBy uuid.UUID) ([]Category, error) {
	rows, err := q.db.QueryContext(ctx, listCategoriesForUserId, createdBy)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []Category
	for rows.Next() {
		var i Category
		if err := rows.Scan(
			&i.ID,
			&i.CreatedAt,
			&i.UpdatedAt,
			&i.Name,
			&i.Description,
			&i.CreatedBy,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const resetCategories = `-- name: ResetCategories :many
DELETE FROM categories
RETURNING id, created_at, updated_at, name, description, created_by
`

func (q *Queries) ResetCategories(ctx context.Context) ([]Category, error) {
	rows, err := q.db.QueryContext(ctx, resetCategories)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []Category
	for rows.Next() {
		var i Category
		if err := rows.Scan(
			&i.ID,
			&i.CreatedAt,
			&i.UpdatedAt,
			&i.Name,
			&i.Description,
			&i.CreatedBy,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const updateCategory = `-- name: UpdateCategory :one
UPDATE categories
SET name = $2, description = $3, updated_at=NOW()
WHERE id = $1
RETURNING id, created_at, updated_at, name, description, created_by
`

type UpdateCategoryParams struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
}

func (q *Queries) UpdateCategory(ctx context.Context, arg UpdateCategoryParams) (Category, error) {
	row := q.db.QueryRowContext(ctx, updateCategory, arg.ID, arg.Name, arg.Description)
	var i Category
	err := row.Scan(
		&i.ID,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.Name,
		&i.Description,
		&i.CreatedBy,
	)
	return i, err
}
