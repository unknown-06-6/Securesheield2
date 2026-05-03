# SecureShield - RBAC API (Mini Project II)

A Python/Flask application implementing secure authentication and Role-Based Access Control (RBAC) using JWT and Flask-Bcrypt.

## Stack

| Library | Purpose |
|---------|---------|
| Flask | Web framework |
| PyJWT | JWT issuance & validation |
| Flask-Bcrypt | Password hashing with salt |

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run the server
python app.py          # defaults to http://127.0.0.1:5000

# 3. (Optional) Run the automated demo
python test_api.py     # server must be running first
```

## Endpoints

| Method | Route | Auth | Role |
|--------|-------|------|------|
| POST | `/register` | None | - |
| POST | `/login` | None | - |
| POST | `/logout` | Bearer JWT | any |
| GET  | `/profile` | Bearer JWT | user or admin |
| DELETE | `/user/<id>` | Bearer JWT | **admin only** |
| GET  | `/users` | Bearer JWT | **admin only** |

## Task Coverage

| Task | Description |
|------|-------------|
| 1 | Flask-Bcrypt salted password hashing at `/register` |
| 2 | JWT issuance with username + role at `/login` |
| 3 | `@token_required` decorator validates every protected route |
| 4 | `/profile` (any role) vs `DELETE /user/<id>` (admin only) |
| 5 | `/logout` blacklists the token in-memory |
| 6 | `security.log` records every 403 with timestamp + action |

## Demo Flow (YouTube)

1. **Register** a user and an admin
2. **Login** as the user - copy the token
3. **GET /profile** - succeeds (200)
4. **DELETE /user/1** with user token - 403 Forbidden (also logged to security.log)
5. **Login** as admin - copy admin token
6. **DELETE /user/<id>** with admin token - 200 OK
7. **POST /logout** - token revoked
8. Re-use the revoked token - 401
9. **Tamper test**: paste token into jwt.io, change `"role":"user"` to `"role":"admin"`, copy modified token, hit any endpoint - 401 Invalid token

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `JWT_SECRET` | `secureshield-secret-key` | HMAC signing key - change in production |
