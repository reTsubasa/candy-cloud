CREATE TABLE development_demo_accounts (
    user_id BINARY(16) NOT NULL PRIMARY KEY,
    email_normalized VARCHAR(254) NOT NULL,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_development_demo_accounts_email (email_normalized),
    CONSTRAINT fk_development_demo_accounts_user FOREIGN KEY (user_id) REFERENCES human_users(id)
) ENGINE=InnoDB;
