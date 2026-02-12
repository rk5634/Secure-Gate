# Secure-Gate / Auth System (Production Ready)

A robust, enterprise-grade authentication and user management system built with Go (Golang). Designed with clean architecture, this system supports modern security standards including OAuth2, JWT, Rate Limiting, and Multi-Factor Authentication (MFA).

## 🌟 Why Secure-Gate? (Advantages)

Unlike simple authentication templates, Secure-Gate is built for **real-world production scenarios**:

1.  **Security First**: Implements **ECDSA** for JWT signing (stronger than RSA/HMAC), **Bcrypt** for password hashing, and strict **Rate Limiting** to prevent DDoS and Brute Force attacks.
2.  **Enterprise Scalability**:
    -   **Stateless Authentication**: JWTs allow horizontal scaling of backend services.
    -   **Distributed Rate Limiting**: Uses Redis, allowing multiple API instances to share rate limit counters.
    -   **Clean Architecture**: The codebase is decoupled (Handler -> Service -> Repository), making it easy to swap databases or add new transport layers (e.g., gRPC) without rewriting business logic.
3.  **User-Centric Features**: Includes the "hard parts" of auth systems out-of-the-box: **Email Verification**, **Forgot Password flows**, and **OAuth2** integration.

## 🚀 Key Features

### 🔐 Authentication & Security
-   **JWT Authentication**: Secure stateless authentication using ECDSA signed tokens.
-   **Google OAuth2**: Seamless login with Google accounts.
-   **Password Security**: Industry-standard `bcrypt` hashing.
-   **Rate Limiting**:
    -   **IP-based**: Prevents abuse from single sources.
    -   **Advanced**: Custom rules (e.g., per user/tier) using Redis with atomic operations.
-   **Role-Based Access Control (RBAC)**: Support for protected routes and user roles.

### 👤 User Management
-   **Registration**: Secure signup with input validation.
-   **Email Verification**: AWS SES integration for verifying user emails.
-   **Profile Updates**: Users can update their verified email address securely with re-verification.
-   **Password Recovery**: Secure Forgot/Reset password flows with temporary tokens.

### 📲 Multi-Factor Authentication
-   **SMS OTP**: Integrated with Twilio for One-Time Password verification, adding a second layer of security.

## 🧠 Advanced Implementations

### Clean Architecture
The project follows strict separation of concerns:
-   **Domain Layer (`internal/models`)**: Pure data structures, no dependencies.
-   **Repository Layer (`internal/repository`)**: Handles database I/O. Uses `pgx` for high-performance PostgreSQL connectivity.
-   **Service Layer (`internal/service`)**: Contains all business logic (hashing, token generation, validation).
-   **Delivery Layer (`internal/handler`)**: HTTP specific logic (Gin context parsing, JSON response).

### Distributed Rate Limiting
Uses **Redis** to strictly limit request rates.
-   **Algorithm**: Token Bucket / Sliding Window (implemented via Redis commands).
-   **Advantage**: Works across a cluster of API servers, ensuring a global rate limit is enforced.

### Asynchronous Communication (Email/SMS)
-   Integrates with **AWS SES** and **Twilio** via interfaces, allowing for easy mocking during tests or swapping providers (e.g., swapping SES for SendGrid) without changing core logic.

## System Workflows

### 1. User Registration & Verification
1.  **User** submits `POST /signup`.
2.  **System** validates input, hashes password, and creates a `User` record (Status: `Unverified`).
3.  **System** generates a secure random token and emails it via **AWS SES**.
4.  **User** clicks link -> `GET /verify-email`.
5.  **System** verifies token, updates `User` status to `Verified`.

### 2. Login Flow (Standard)
1.  **User** submits `POST /login` (Email + Password).
2.  **System** fetches user, compares hash (`bcrypt`).
3.  **System** generates an **ECDSA** signed JWT.
4.  **System** returns JWT. Client stores it (e.g., HTTPOnly Cookie or storage).

### 3. Google OAuth Flow
1.  **User** clicks "Login with Google" -> `GET /oauth/google/login`.
2.  **System** redirects user to Google's consent screen.
3.  **Google** redirects back to `/oauth/google/callback` with a `code`.
4.  **System** exchanges `code` for Google Profile Data.
5.  **System** finds or creates the user in DB and issues a JWT.

## 🛠️ Tech Stack

-   **Language**: Go 1.24+
-   **Framework**: Gin Web Framework
-   **Database**: PostgreSQL
-   **Cache/KV Store**: Redis
-   **Cloud Infrastructure**: AWS SES, Twilio, Google Cloud
-   **Tools**: Docker, Docker Compose, Make, migrate

## ⚡ Getting Started

### Prerequisites

-   Go 1.24+
-   Docker & Docker Compose
-   **External Services Accounts**: Google Cloud, AWS SES, Twilio.

### 1. Environment Configuration

Create a `.env` file in `configs/` (e.g., `prod.env`) with the following keys:

```env
PORT=8080
DB_URL=postgres://user:pass@localhost:5432/dbname
REDIS_URL=redis://localhost:6379
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
GOOGLE_REDIRECT_URL=http://localhost:8080/oauth/google/callback
AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID=your_aws_key
AWS_SECRET_ACCESS_KEY=your_aws_secret
SENDER_EMAIL=noreply@yourdomain.com
TWILIO_ACCOUNT_SID=your_twilio_sid
TWILIO_AUTH_TOKEN=your_twilio_token
TWILIO_SERVICE_SID=your_twilio_verify_sid
JWT_PRIVATE_KEY=your_ecdsa_private_key
JWT_PUBLIC_KEY=your_ecdsa_public_key
```

### 2. Run with Docker

```bash
docker-compose up -d --build
```

### 3. Run Locally

Ensure PostgreSQL and Redis are running, then:

```bash
go run cmd/server/main.go
```

## 🔌 API Endpoints

### Public Routes (Rate Limited)

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/` | Health Check |
| `POST` | `/signup` | Register new user |
| `POST` | `/login` | User login (returns JWT) |
| `GET` | `/oauth/google/login` | Initiate Google OAuth |
| `GET` | `/oauth/google/callback`| Google OAuth Callback |
| `GET` | `/verify-email` | Confirm email verification token |
| `POST` | `/resend-email-verification` | Request new verification email |
| `POST` | `/forgot-password` | Initiate password reset |
| `POST` | `/reset-password` | Complete password reset |
| `POST` | `/send-otp` | Send SMS OTP |
| `POST` | `/verify-otp` | Verify SMS OTP |
| `PUT` | `/update-email` | Update user email address |

### Protected Routes (Requires JWT)

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/me` | Get current user profile |

### Advanced Rate Limited Routes

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/refresh` | Refresh Access Token |
| `POST` | `/logout` | Logout (Invalidate token) |
