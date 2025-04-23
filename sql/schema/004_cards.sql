-- +goose Up
CREATE TABLE cards (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    owner UUID NOT NULL,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    CONSTRAINT fk_owner FOREIGN KEY (owner) REFERENCES users (id) ON DELETE CASCADE
);

-- +goose Down
DROP TABLE cards;
