-- +goose Up
CREATE TABLE active_subscriptions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    subscription_id UUID NOT NULL,
    user_id UUID NOT NULL,
    card_id UUID NOT NULL,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL,
    billing_frequency TEXT NOT NULL,
    auto_renew_enabled BOOLEAN DEFAULT true,
    CONSTRAINT fk_subscription_id FOREIGN KEY (subscription_id) REFERENCES subscriptions (id) ON DELETE CASCADE,
    CONSTRAINT fk_user_id FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    CONSTRAINT fk_card_id FOREIGN KEY (card_id) REFERENCES cards (id) ON DELETE CASCADE
);

-- +goose Down
DROP TABLE active_subscriptions;
