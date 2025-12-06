## Key Technologies Used

-   **Django-Ninja**: This framework is used to build the API endpoints. It provides a FastAPI-like experience for Django projects, leveraging Python type hints for automatic validation, serialization, and interactive API documentation.

-   **Google (for OAuth)**: Integrated for secure user authentication. It allows users to log in using their existing Google accounts, streamlining the registration and login process.

-   **Paystack API Wrapper**: This library simplifies integration with the Paystack payment gateway. It provides an easy-to-use interface for initiating and verifying payments, as well as handling webhooks.

-   **python-dotenv**: This library loads environment variables from a `.env` file into `os.environ`. It ensures that sensitive configurations like API keys and secrets are kept out of the codebase and managed securely.

-   **PostgreSQL**: Chosen as the relational database for its robustness, scalability, and reliability in production environments. It provides strong data integrity and a rich feature set that is well-suited for applications requiring transactional consistency.
