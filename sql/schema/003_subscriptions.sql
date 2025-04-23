-- +goose Up
CREATE TABLE subscriptions(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL,
    monthly_cost_sek INTEGER NOT NULL,
    unsubscribe_url TEXT,
    category_id UUID NOT NULL,
    created_by UUID NOT NULL,
    CONSTRAINT fk_category_id FOREIGN KEY (category_id) REFERENCES categories (id) ON DELETE CASCADE,
    CONSTRAINT fk_created_by FOREIGN KEY (created_by) REFERENCES users (id) ON DELETE CASCADE
);

-- +goose Down
DROP TABLE subscriptions;
