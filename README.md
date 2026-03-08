# 🔐 Trainer Hub - Auth Service

[![Kotlin](https://img.shields.io/badge/Kotlin-1.9+-purple.svg)](https://kotlinlang.org/)
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.2+-green.svg)](https://spring.io/projects/spring-boot)
[![License](https://img.shields.io/badge/License-Private-red.svg)](LICENSE)
[![CI/CD](https://github.com/MateusO97/trainer-hub-auth-service/workflows/CI/badge.svg)](https://github.com/MateusO97/trainer-hub-auth-service/actions)

**Authentication & Authorization Service** for Trainer Hub platform.

Provides OAuth2 authentication, JWT token management, RBAC (Role-Based Access Control), and audit logging.

---

## 📋 Table of Contents

- [Features](#-features)
- [Tech Stack](#-tech-stack)
- [Getting Started](#-getting-started)
- [API Documentation](#-api-documentation)
- [Testing](#-testing)
- [Deployment](#-deployment)
- [Contributing](#-contributing)

---

## 🎯 Features

✅ **Email + Password Authentication** - Secure bcrypt hashing (cost 12)  
✅ **OAuth2 Integration** - Google + Apple Sign-In  
✅ **JWT Token Management** - Access (1h) + Refresh tokens (7d)  
✅ **RBAC** - 4 roles (USER, NUTRITIONIST, TRAINER, ADMIN)  
✅ **Password Reset Flow** - Email-based secure reset  
✅ **Audit Logging** - All authentication events tracked  

---

## 🛠 Tech Stack

| Component | Technology | Version |
|-----------|-----------|---------|
| **Language** | Kotlin | 1.9+ |
| **Framework** | Spring Boot | 3.2+ |
| **Database** | PostgreSQL | 15+ |
| **Cache** | Redis | 7.0+ |
| **Auth** | Spring Security | 6.0+ |
| **JWT** | java-jwt | 0.12.1 |

---

## 🚀 Getting Started

### Prerequisites

- JDK 17+
- Docker
- PostgreSQL 15+ (via Docker)
- Redis 7.0+ (via Docker)

### Quick Start

```bash
# 1. Clone repository
git clone https://github.com/MateusO97/trainer-hub-auth-service.git
cd trainer-hub-auth-service

# 2. Start infrastructure
docker-compose up -d

# 3. Run migrations
./gradlew flywayMigrate

# 4. Build & run
./gradlew bootRun
```

Service starts on `http://localhost:8081`

---

## 📖 API Documentation

### Endpoints

- `POST /api/v1/auth/login` - Email + password login
- `POST /api/v1/auth/oauth/google` - Google OAuth2
- `POST /api/v1/auth/oauth/apple` - Apple Sign In
- `POST /api/v1/auth/refresh` - Refresh access token
- `POST /api/v1/auth/logout` - Invalidate tokens
- `GET /api/v1/auth/me` - Current user info
- `POST /api/v1/auth/password-reset` - Request reset
- `POST /api/v1/auth/password-reset-confirm` - Confirm reset
- `POST /api/v1/auth/validate-token` - Validate JWT

**Full documentation**: [docs/API.md](docs/API.md)

---

## 🧪 Testing

```bash
# Run tests
./gradlew test

# With coverage
./gradlew test jacocoTestReport

# Coverage target: ≥80%
```

---

## 🐳 Deployment

```bash
# Build Docker image
docker build -t trainer-hub-auth-service:latest .

# Run with Docker Compose
docker-compose up -d
```

---

## 🤝 Contributing

1. Read [Development Standards](https://github.com/MateusO97/trainer-hub-docs)
2. Create feature branch: `feature/AUTH-XXX-description`
3. Follow code standards: `./gradlew ktlintFormat`
4. Write tests (≥80% coverage)
5. Commit following [Conventional Commits](https://www.conventionalcommits.org/)
6. Open PR with template

---

## 📚 Documentation

- **[REQUIREMENTS.md](docs/REQUIREMENTS.md)** - Complete requirements
- **[API.md](docs/API.md)** - API specification
- **[ARCHITECTURE.md](docs/ARCHITECTURE.md)** - Architecture decisions
- **[DEPLOYMENT.md](docs/DEPLOYMENT.md)** - Deployment guide

---

**Last Updated**: March 8, 2026 | **Version**: 1.0.0 | **Status**: 🏗️ In Development
