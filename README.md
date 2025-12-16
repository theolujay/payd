# payd API

A lean wallet service built with Django Ninja. Integrates Google OAuth for authentication, Paystack for payments, and permissioned API keys for service-to-service access. Users can deposit money, track transactions, manage balances, and transfer funds securely. Swagger UI is included for full endpoint exploration.

## Features

* **Authentication:** Google OAuth + JWT for users. API keys for services with scoped permissions and expiry.
* **Wallet:** One wallet per user, real-time balance updates, transaction history, and wallet-to-wallet transfers.
* **Payments (Paystack):** Deposit initialization, transaction verification, and webhook handling for crediting.
* **API Keys:** Create, list, revoke, and roll over keys. Max 5 active keys per user.
* **Background Tasks (Celery):**
    * **Paystack Transaction Verification:** Automatically verifies pending Paystack transactions every hour and updates wallet balances accordingly.
    * **API Key Revocation:** Automatically revokes expired API keys every 45 minutes to enhance security.

## Core Flows

### Authentication

* Google sign-in returns JWT tokens.
* API requests may use either:

  * `Authorization: Bearer <token>`
  * `x-api-key: <key>` (with permission checks)

### Deposits

1. Client hits `/wallet/deposit` with amount.
2. Server initializes Paystack transaction and returns `authorization_url` + `reference`.
3. User pays via Paystack.
4. Paystack webhook hits `/wallet/paystack/webhook`.
5. Signature is verified; wallet credited on confirmed success.
   Only the webhook can credit wallets.

### Transfers

* Atomic wallet-to-wallet transfers with balance validation.
* Transaction logs recorded for both parties.

### API Keys

* Create keys with permissions like `read`, `deposit`, or `transfer`.
* Keys expire (`1H`, `1D`, `1M`, `1Y`), can be revoked, and support rollover.

## Endpoints

Swagger UI: `/api/docs`

Base prefix for all endpoints: `/api/`


* **Auth:** `/auth/google`, `/auth/google/callback`, `/auth/token/refresh`
* **API Keys:** `/auth/keys`, `/auth/keys/create`, `/auth/keys/rollover`, `/auth/keys/{id}/revoke`
* **Wallet:** `/wallet/balance`, `/wallet/deposit`, `/wallet/transfer`, `/wallet/transactions`, `/wallet/transaction/{reference}/status`
* **Webhook:** `/wallet/paystack/webhook`

## Highlights

* Webhooks are fully idempotent.
* Transfers and credits run inside DB transactions.
* Deposit references are unique and safely verified.
* API keys stored hashed; only shown once on creation.

## Setup

```bash
git clone https://github.com/theolujay/payd

cd payd

python -m venv .venv

source .venv/bin/activate

pip install -r requirements.txt

# Make sure you have Redis running
# e.g., docker run -d -p 6379:6379 redis

cp .example.env .env 

# Update .env with your credentials, including:
# CELERY_BROKER_URL=redis://localhost:6379/0
# CELERY_RESULT_BACKEND=redis://localhost:6379/0

python manage.py migrate

python manage.py runserver

# In a separate terminal, run the Celery worker and beat
celery -A payd worker -l info
celery -A payd beat -l info --scheduler django_celery_beat.schedulers:DatabaseScheduler
```

Docker:

```bash
# This will start the app, database, redis, celery worker and celery beat
docker compose up --build
```