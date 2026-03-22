-- PerpDex Combined Schema Initialization
-- Combines api-service and settlement-service migrations
-- for single-shot Postgres initialization via docker-entrypoint-initdb.d

BEGIN;

-- ===========================================================
-- Extensions
-- ===========================================================
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ===========================================================
-- API Service Tables (from api-service/migrations/0001)
-- ===========================================================

CREATE TABLE IF NOT EXISTS nonces (
    nonce TEXT PRIMARY KEY,
    issued_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    is_used BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    address VARCHAR(40) NOT NULL,
    name VARCHAR(24) NOT NULL,
    api_key TEXT UNIQUE NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMPTZ NOT NULL,
    secret_type TEXT NOT NULL,
    secret_key TEXT NOT NULL,
    nonce BIGINT,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT users_address_name_key UNIQUE (address, name)
);

CREATE INDEX IF NOT EXISTS idx_users_address ON users (address);
CREATE INDEX IF NOT EXISTS idx_users_api_key ON users (api_key);

CREATE TABLE IF NOT EXISTS user_request (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    endpoint TEXT NOT NULL,
    request_body JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_user_request_user_id ON user_request (user_id);

CREATE TABLE IF NOT EXISTS trade (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    trade_id BIGINT NOT NULL,
    product_id BIGINT NOT NULL,
    symbol TEXT NOT NULL,
    price NUMERIC(38, 0) NOT NULL,
    qty NUMERIC(38, 0) NOT NULL,
    quote_qty NUMERIC(38, 0) NOT NULL GENERATED ALWAYS AS (price * qty) STORED,
    time BIGINT NOT NULL,
    is_buyer_maker BOOLEAN NOT NULL,
    is_best_match BOOLEAN NOT NULL,
    side TEXT NOT NULL,
    taker_order_id UUID NOT NULL,
    maker_order_id UUID NOT NULL,
    taker_id UUID NOT NULL,
    maker_id UUID NOT NULL,
    request_id UUID NOT NULL,
    flag CHARACTER(1),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT trade_symbol_trade_id_key UNIQUE (symbol, trade_id)
);

CREATE INDEX IF NOT EXISTS idx_trade_symbol_time ON trade (symbol, time DESC);
CREATE INDEX IF NOT EXISTS idx_trade_product_id ON trade (product_id);

CREATE TABLE IF NOT EXISTS agg_trade (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    trade_id BIGINT NOT NULL,
    product_id BIGINT NOT NULL,
    symbol TEXT NOT NULL,
    price NUMERIC(38, 0) NOT NULL,
    qty NUMERIC(38, 0) NOT NULL,
    first_trade_id BIGINT NOT NULL,
    last_trade_id BIGINT NOT NULL,
    time BIGINT NOT NULL,
    is_buyer_maker BOOLEAN NOT NULL,
    is_best_match BOOLEAN NOT NULL,
    request_id UUID NOT NULL,
    flag CHARACTER(1),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT agg_trade_symbol_trade_id_key UNIQUE (symbol, trade_id)
);

CREATE INDEX IF NOT EXISTS idx_agg_trade_symbol_time ON agg_trade (symbol, time DESC);
CREATE INDEX IF NOT EXISTS idx_agg_trade_product_id ON agg_trade (product_id);

CREATE TABLE IF NOT EXISTS kline (
    symbol TEXT NOT NULL,
    interval TEXT NOT NULL,
    open_time BIGINT NOT NULL,
    open NUMERIC(38, 0) NOT NULL,
    high NUMERIC(38, 0) NOT NULL,
    low NUMERIC(38, 0) NOT NULL,
    close NUMERIC(38, 0) NOT NULL,
    volume NUMERIC(38, 0) NOT NULL,
    close_time BIGINT NOT NULL,
    quote_volume NUMERIC(38, 0) NOT NULL,
    trade_num BIGINT NOT NULL,
    taker_buy_volume NUMERIC(38, 0) NOT NULL,
    taker_buy_quote_volume NUMERIC(38, 0) NOT NULL,
    first_trade_id BIGINT,
    last_trade_id BIGINT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (symbol, interval, open_time)
);

CREATE INDEX IF NOT EXISTS idx_klines_latest ON kline (symbol, interval, open_time DESC);

CREATE TABLE IF NOT EXISTS orders (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users (id),
    symbol TEXT NOT NULL,
    product_id BIGINT NOT NULL,
    client_order_id TEXT NOT NULL,
    price NUMERIC(39, 0) NOT NULL,
    orig_qty NUMERIC(39, 0) NOT NULL,
    executed_qty NUMERIC(39, 0) NOT NULL DEFAULT 0,
    orig_quote_order_qty NUMERIC(39, 0) NOT NULL DEFAULT 0,
    cummulative_quote_qty NUMERIC(39, 0) NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'NEW',
    time_in_force TEXT NOT NULL DEFAULT 'GTC',
    order_type TEXT NOT NULL,
    side TEXT NOT NULL,
    time BIGINT NOT NULL,
    update_time BIGINT NOT NULL,
    is_working BOOLEAN NOT NULL DEFAULT TRUE,
    working_time BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    stop_price NUMERIC(39, 0),
    iceberg_qty NUMERIC(39, 0),
    self_trade_prevention_mode TEXT,
    request_id UUID NOT NULL,
    flag CHARACTER(1),
    CONSTRAINT orders_user_client_order_id_key UNIQUE (user_id, client_order_id)
);

CREATE INDEX IF NOT EXISTS idx_orders_user_id ON orders (user_id);
CREATE INDEX IF NOT EXISTS idx_orders_symbol ON orders (symbol);
CREATE INDEX IF NOT EXISTS idx_orders_status ON orders (status);
CREATE INDEX IF NOT EXISTS idx_orders_user_symbol_status ON orders (user_id, symbol);

CREATE TABLE IF NOT EXISTS open_interest (
    id BIGSERIAL PRIMARY KEY,
    product_id BIGINT NOT NULL,
    interest BIGINT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT open_interest_product_interest_update UNIQUE (product_id, interest, updated_at)
);

CREATE INDEX IF NOT EXISTS idx_open_interest_product_update ON open_interest (product_id, updated_at DESC);

CREATE TABLE IF NOT EXISTS commission_rates (
    id SERIAL PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users (id),
    symbol TEXT NOT NULL,
    product_id BIGINT NOT NULL,
    maker_commission NUMERIC(39, 0) NOT NULL DEFAULT 0,
    taker_commission NUMERIC(39, 0) NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT commission_rates_user_symbol_key UNIQUE (user_id, symbol)
);

CREATE INDEX IF NOT EXISTS idx_commission_rates_user_id ON commission_rates (user_id);
CREATE INDEX IF NOT EXISTS idx_commission_rates_symbol ON commission_rates (symbol);

CREATE TABLE IF NOT EXISTS user_balance (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id UUID NOT NULL,
    product_id BIGINT NOT NULL,
    amount NUMERIC(38, 0) NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT user_balance_user_id_product_id UNIQUE (user_id, product_id)
);

CREATE TABLE IF NOT EXISTS user_perp_balance (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id UUID UNIQUE NOT NULL,
    context TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS user_balance_transfer (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    nonce BIGINT NOT NULL,
    product_id BIGINT NOT NULL,
    amount NUMERIC(38, 0) NOT NULL,
    deposit_idx BIGINT,
    transfer_type TEXT NOT NULL,
    perp_position_snapshot TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT user_balance_transfer_user_id_nonce UNIQUE (user_id, nonce)
);

CREATE INDEX IF NOT EXISTS idx_user_balance_transfer_user_id ON user_balance_transfer (user_id);

CREATE TABLE IF NOT EXISTS orderbook_nonce (
    product_id BIGINT PRIMARY KEY,
    nonce BIGINT NOT NULL,
    transaction_id BIGINT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS orderbook (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    request_id UUID NOT NULL,
    product_id BIGINT NOT NULL,
    nonce BIGINT NOT NULL,
    content TEXT NOT NULL,
    content_type TEXT NOT NULL,
    perp_position_snapshot TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT orderbook_product_id_nonce UNIQUE (product_id, nonce)
);

CREATE TABLE IF NOT EXISTS orderbook_snapshot (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    order_map TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS leverage (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    nonce BIGINT NOT NULL,
    product_id BIGINT NOT NULL,
    perp_position_snapshot TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT leverage_user_id_nonce UNIQUE (user_id, nonce)
);

CREATE TABLE IF NOT EXISTS funding_log (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id UUID NOT NULL,
    product_id BIGINT NOT NULL,
    fee BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT funding_log_id_fee_created UNIQUE (user_id, product_id, fee, created_at)
);

CREATE INDEX IF NOT EXISTS idx_funding_log_user_id_craeted ON funding_log (user_id, created_at DESC);

-- ===========================================================
-- Settlement Service Tables
-- ===========================================================

-- chain_tx (0003)
CREATE TABLE IF NOT EXISTS chain_tx (
    id BIGSERIAL PRIMARY KEY,
    task_id BIGINT NOT NULL,
    sender_id BIGINT NOT NULL,
    nonce BIGINT NOT NULL,
    tx_hash VARCHAR(66) NOT NULL UNIQUE,
    status VARCHAR(32) NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_task_id ON chain_tx(task_id);
CREATE INDEX IF NOT EXISTS idx_sender_id ON chain_tx(sender_id);
CREATE INDEX IF NOT EXISTS idx_tx_hash ON chain_tx(tx_hash);
CREATE INDEX IF NOT EXISTS idx_sender_nonce ON chain_tx(sender_id, nonce);
CREATE INDEX IF NOT EXISTS idx_status ON chain_tx(status);

-- deposit_collateral_calls
CREATE TABLE IF NOT EXISTS deposit_collateral_calls (
    idx BIGSERIAL PRIMARY KEY,
    subaccount_id UUID NOT NULL,
    product_id BIGINT NOT NULL,
    amount BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_deposit_calls_subaccount_id ON deposit_collateral_calls(subaccount_id);
CREATE INDEX IF NOT EXISTS idx_deposit_calls_product_id ON deposit_collateral_calls(product_id);
CREATE INDEX IF NOT EXISTS idx_deposit_calls_amount ON deposit_collateral_calls(amount);
CREATE INDEX IF NOT EXISTS idx_deposit_calls_created_at ON deposit_collateral_calls(created_at);

-- update_price_pos
CREATE TABLE IF NOT EXISTS update_price_pos (
    idx BIGSERIAL PRIMARY KEY,
    product_id BIGINT NOT NULL,
    price BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_update_price_pos_product_id ON update_price_pos(product_id);
CREATE INDEX IF NOT EXISTS idx_update_price_pos_price ON update_price_pos(price);
CREATE INDEX IF NOT EXISTS idx_update_price_pos_created_at ON update_price_pos(created_at);
CREATE INDEX IF NOT EXISTS idx_update_price_pos_product_created ON update_price_pos(product_id, created_at);

-- match_orders
CREATE TABLE IF NOT EXISTS match_orders (
    idx BIGSERIAL PRIMARY KEY,
    product_id BIGINT NOT NULL,
    taker_subaccount_id UUID NOT NULL,
    taker_price BIGINT NOT NULL,
    taker_amount BIGINT NOT NULL,
    taker_expiration BIGINT NOT NULL,
    taker_nonce BIGINT NOT NULL,
    maker_subaccount_id UUID NOT NULL,
    maker_price BIGINT NOT NULL,
    maker_amount BIGINT NOT NULL,
    maker_expiration BIGINT NOT NULL,
    maker_nonce BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_match_orders_product_id ON match_orders(product_id);
CREATE INDEX IF NOT EXISTS idx_match_orders_taker_subaccount ON match_orders(taker_subaccount_id);
CREATE INDEX IF NOT EXISTS idx_match_orders_maker_subaccount ON match_orders(maker_subaccount_id);
CREATE INDEX IF NOT EXISTS idx_match_orders_taker_nonce ON match_orders(taker_nonce);
CREATE INDEX IF NOT EXISTS idx_match_orders_maker_nonce ON match_orders(maker_nonce);
CREATE INDEX IF NOT EXISTS idx_match_orders_created_at ON match_orders(created_at);
CREATE INDEX IF NOT EXISTS idx_match_orders_product_created ON match_orders(product_id, created_at);

-- execute_slow_modes
CREATE TABLE IF NOT EXISTS execute_slow_modes (
    idx BIGSERIAL PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_execute_slow_modes_created_at ON execute_slow_modes(created_at);

-- tx_req_indexes
CREATE TABLE IF NOT EXISTS tx_req_indexes (
    idx BIGSERIAL PRIMARY KEY,
    type VARCHAR(32) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_tx_req_indexes_type ON tx_req_indexes(type);
CREATE INDEX IF NOT EXISTS idx_tx_req_indexes_created_at ON tx_req_indexes(created_at);
CREATE INDEX IF NOT EXISTS idx_tx_req_indexes_type_created ON tx_req_indexes(type, created_at);

-- withdraw_collaterals
CREATE TABLE IF NOT EXISTS withdraw_collaterals (
    idx BIGSERIAL PRIMARY KEY,
    subaccount_id UUID NOT NULL,
    product_id BIGINT NOT NULL,
    amount BIGINT NOT NULL,
    nonce BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_withdraw_collaterals_subaccount_id ON withdraw_collaterals(subaccount_id);
CREATE INDEX IF NOT EXISTS idx_withdraw_collaterals_product_id ON withdraw_collaterals(product_id);
CREATE INDEX IF NOT EXISTS idx_withdraw_collaterals_amount ON withdraw_collaterals(amount);
CREATE INDEX IF NOT EXISTS idx_withdraw_collaterals_nonce ON withdraw_collaterals(nonce);
CREATE INDEX IF NOT EXISTS idx_withdraw_collaterals_created_at ON withdraw_collaterals(created_at);
CREATE INDEX IF NOT EXISTS idx_withdraw_collaterals_subaccount_product ON withdraw_collaterals(subaccount_id, product_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_withdraw_collaterals_subaccount_nonce ON withdraw_collaterals(subaccount_id, nonce);

-- deposit_events
CREATE TABLE IF NOT EXISTS deposit_events (
    id BIGSERIAL PRIMARY KEY,
    subaccount UUID NOT NULL,
    product_id INTEGER NOT NULL,
    amount INT8 NOT NULL,
    referral_code TEXT NOT NULL,
    block INT8 NOT NULL,
    tx_index INTEGER NOT NULL,
    tx_hash VARCHAR(66) NOT NULL,
    log_index INTEGER NOT NULL,
    status VARCHAR(16) NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_deposit_events_status ON deposit_events(status);
CREATE INDEX IF NOT EXISTS idx_deposit_events_id ON deposit_events(id);
CREATE INDEX IF NOT EXISTS idx_deposit_events_subaccount ON deposit_events(subaccount);
CREATE UNIQUE INDEX IF NOT EXISTS idx_deposit_events_tx_hash ON deposit_events(tx_hash, log_index);
CREATE UNIQUE INDEX IF NOT EXISTS uk_deposit_events_block_tx_log ON deposit_events(block, tx_index, log_index);
CREATE INDEX IF NOT EXISTS idx_deposit_events_status_id ON deposit_events(status, id);

-- kv_store
CREATE TABLE IF NOT EXISTS kv_store (
    name VARCHAR(64) PRIMARY KEY,
    str VARCHAR(128) NOT NULL,
    num BIGINT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_kv_store_num ON kv_store(num);
CREATE INDEX IF NOT EXISTS idx_kv_store_name_num ON kv_store(name, num);

COMMIT;
