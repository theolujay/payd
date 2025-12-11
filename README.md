# payd API

A Django API for user authentication via Google OAuth, wallet management, and payment processing with Paystack.

## Features

-   **User Authentication:** User sign-up and sign-in via Google OAuth and JWT.
-   **Wallet Management:** Deposit funds, check balances, view transaction history, and perform wallet-to-wallet transfers.
-   **API Key Management:** Create, list, rollover, and revoke API keys with fine-grained permissions.
-   **Payment Processing:** Integration with Paystack for payment initiation, webhooks, and transaction status verification.

## Project Setup

1.  **Clone the repository:**
    ```bash
    git clone <repository-url>
    cd payd
    ```

2.  **Set up the environment:**

    This project uses `uv` for package management.

    ```bash
    # Create and activate a virtual environment
    python -m venv .venv
    source .venv/bin/activate

    # Sync the environment with the lock file
    uv sync
    ```

3.  **Configure environment variables:**

    Create a `.env` file in the project root by copying the example file:

    ```bash
    cp .env.example .env
    ```

    Open the .env file and fill in the required secret keys.

4.  **Run database migrations:**
    ```bash
    python manage.py migrate
    ```

5.  **Start the development server:**
    ```bash
    python manage.py runserver
    ```
    The API will be available at `http://127.0.0.1:8000`.

## API Endpoints

All endpoints are available under the `/api/` prefix.

### Authentication

-   `GET /auth/google`: Initiate Google OAuth flow to get the authorization URL.
-   `GET /auth/google/callback`: Google OAuth callback to exchange authorization code for JWT tokens (access and refresh).
-   `POST /auth/token/refresh`: Refresh an expired access token using a valid refresh token.

### User Management

-   `GET /user/profile`: Retrieve the authenticated user's profile information. (Requires JWT)

### Wallet Management

-   `POST /wallet/deposit`: Initiate a wallet deposit via Paystack. (Requires JWT or API Key with 'deposit' permission)
-   `GET /wallet/balance`: Get the authenticated user's current wallet balance. (Requires JWT or API Key with 'read' permission)
-   `POST /wallet/transfer`: Perform a wallet-to-wallet transfer to another user. (Requires JWT or API Key with 'transfer' permission)
-   `GET /wallet/transactions`: Get the authenticated user's transaction history. (Requires JWT or API Key with 'read' permission)
-   `GET /wallet/transaction/{reference}/status`: Get the status of a specific transaction by its reference. (Requires JWT or API Key with 'read' permission)

### API Key Management

-   `POST /auth/keys/create`: Create a new API key with specified name, permissions, and expiry. (Requires JWT)
-   `POST /auth/keys/rollover`: Rollover an expired API key, generating a new one with the same details. (Requires JWT)
-   `POST /auth/keys/{key_id}/revoke`: Revoke an active API key by its ID. (Requires JWT)
-   `GET /auth/keys`: List all API keys associated with the authenticated user. (Requires JWT)

### Webhooks

-   `POST /webhooks/paystack`: Paystack webhook endpoint for receiving payment notifications and updating transaction statuses.