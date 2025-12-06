# payd API

A simple Django API for handling user authentication via Google OAuth and processing payments with Paystack.

## Features

- User authentication with Google
- Payment processing via Paystack
- Secure configuration using environment variables

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

    Open the `.env` file and fill in the required secret keys for Django, Google, and Paystack.

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

-   `GET /auth/google`
-   `GET /auth/google/callback`

### Payments

-   `POST /payments/paystack/initiate`
-   `POST /payments/paystack/webhook`
-   `GET /payments/{reference}/status`
