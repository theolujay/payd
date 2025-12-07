# PayD API Documentation

This document provides a comprehensive guide to the PayD API, which allows you to integrate payment functionalities into your applications.

## Base URL

The base URL for all API endpoints is:

```
https://your-domain.com/api/
```

## Authentication

Authentication is handled via Google OAuth 2.0.

### 1. Initiate Google Login

Redirect the user to this endpoint to start the Google authentication flow.

-   **Endpoint:** `GET /auth/google`
-   **Description:** Initiates the Google OAuth 2.0 authentication process. The user will be redirected to the Google login page.
-   **Success Response:** Redirects to Google's authentication page.

### 2. Google Callback

After the user authenticates with Google, they will be redirected to this endpoint.

-   **Endpoint:** `GET /auth/google/callback`
-   **Description:** Handles the callback from Google after the user has authenticated. It exchanges the authorization code for an access token and retrieves the user's information.
-   **Query Parameters:**
    -   `code` (string, required): The authorization code provided by Google.
-   **Success Response (200 OK):**
    ```json
    {
      "user_id": "string",
      "email": "string",
      "name": "string"
    }
    ```
-   **Error Responses:**
    -   `400 Bad Request`: If the authorization code is missing.
    -   `500 Internal Server Error`: If there is an issue with the OAuth configuration or communication with Google.

## Payments

The Payments API allows you to initiate and manage payments.

### 1. Initiate Payment

-   **Endpoint:** `POST /payments/paystack/initiate`
-   **Description:** Initiates a new payment transaction with Paystack.
-   **Request Body:** `application/json`
    ```json
    {
      "amount": "integer",
      "email": "string (optional)"
    }
    ```
    -   `amount`: The amount to be paid in the smallest currency unit (e.g., Kobo for NGN). Must be greater than 0.
    -   `email`: The customer's email address.
-   **Success Response (201 Created):**
    ```json
    {
      "reference": "string",
      "authorization_url": "string"
    }
    ```
    -   `reference`: The unique reference for the transaction.
    -   `authorization_url`: The URL to which the user should be redirected to complete the payment.
-   **Error Responses:**
    -   `400 Bad Request`: If the request body is invalid (e.g., amount is not greater than 0).
    -   `402 Payment Required`: If the payment initiation fails with Paystack.
    -   `500 Internal Server Error`: For any other server-side errors.

### 2. Paystack Webhook

-   **Endpoint:** `POST /payments/paystack/webhook`
-   **Description:** An endpoint for Paystack to send webhook notifications about transaction status changes.
-   **Request Headers:**
    -   `x-paystack-signature`: The signature to verify the webhook's authenticity.
-   **Request Body:** The raw JSON payload from Paystack.
-   **Success Response (200 OK):**
    ```json
    {
      "status": true
    }
    ```
-   **Error Responses:**
    -   `400 Bad Request`: If the signature is invalid or the payload is malformed.

### 3. Get Transaction Status

-   **Endpoint:** `GET /payments/{reference}/status`
-   **Description:** Retrieves the status of a specific transaction.
-   **URL Parameters:**
    -   `reference` (string, required): The unique reference of the transaction.
-   **Query Parameters:**
    -   `refresh` (boolean, optional): If `true`, the status will be refreshed from Paystack's API. Defaults to `false`.
-   **Success Response (200 OK):**
    ```json
    {
      "reference": "string",
      "status": "string",
      "amount": "integer",
      "paid_at": "datetime (optional)",
      "currency": "string"
    }
    ```
    -   `status`: Can be `pending`, `success`, or `failed`.
-   **Error Responses:**
    -   `400 Bad Request`: If the transaction reference is in an invalid format.
    -   `404 Not Found`: If the transaction with the given reference does not exist.

## Health Check
-   **Endpoint:** `GET /`
-   **Description:** Returns a welcome message, indicating that the API is running.
-   **Success Response (200 OK):**
    ```json
    {
      "message": "Welcome to PayD API!"
    }
    ```

## Data Models

### User

The `User` model represents a user in the system.

| Field               | Type         | Description                                        |
| ------------------- | ------------ | -------------------------------------------------- |
| `id`                | UUID         | The unique identifier for the user.                |
| `email`             | String       | The user's email address (unique).                 |
| `is_email_verified` | Boolean      | Whether the user's email has been verified.      |
| `first_name`        | String       | The user's first name.                             |
| `last_name`         | String       | The user's last name.                              |
| `phone`             | String       | The user's phone number (optional).                |
| `username`          | String       | The user's username (unique).                      |
| `google_id`         | String       | The user's Google ID (unique, optional).           |
| `picture_url`       | String       | The URL of the user's profile picture (optional).  |

### Transaction

The `Transaction` model represents a payment transaction.

| Field                 | Type      | Description                                                              |
| --------------------- | --------- | ------------------------------------------------------------------------ |
| `id`                  | UUID      | The unique identifier for the transaction.                               |
| `reference`           | String    | The unique reference for the transaction from Paystack.                  |
| `user`                | FK (User) | The user who initiated the transaction (optional).                       |
| `amount`              | BigInt    | The amount of the transaction in the smallest currency unit (e.g., Kobo). |
| `currency`            | String    | The currency of the transaction (e.g., "NGN").                           |
| `status`              | String    | The status of the transaction (`pending`, `success`, or `failed`).        |
| `authorization_url`   | URL       | The URL for the user to complete the payment.                            |
| `paid_at`             | DateTime  | The timestamp when the transaction was paid (optional).                  |
| `created_at`          | DateTime  | The timestamp when the transaction was created.                          |
| `updated_at`          | DateTime  | The timestamp when the transaction was last updated.                     |

## Error Handling

The API uses standard HTTP status codes to indicate the success or failure of a request. In case of an error, the response body will contain a `detail` field with a description of the error.

| Status Code | Description              |
| ----------- | ------------------------ |
| `400`       | Bad Request              |
| `401`       | Unauthorized             |
| `402`       | Payment Required         |
| `404`       | Not Found                |
| `500`       | Internal Server Error    |

## Running the Project

To run the project locally, follow these steps:

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

## API Documentation

The API documentation is automatically generated and available at `http://localhost:8000/api/docs`.
