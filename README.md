# Task 7: Advanced API Usage and External API Integration

A Node.js + Express app with GitHub OAuth login, an external weather API, rate limiting and error handling.

## 1. OAuth (Login with GitHub)

OAuth 2.0 lets a user log in to my app using an existing account (GitHub) without sharing their password with my app. I implemented the **Authorization Code flow**:

1. The user clicks "Continue with GitHub" and my server redirects them to GitHub with my `client_id` and a random `state`.
2. The user logs in on GitHub and approves access.
3. GitHub redirects back to my callback URL with a temporary `code` and the same `state`.
4. My server checks that the `state` matches (protects against CSRF attacks).
5. My server exchanges the `code` plus my `client_secret` for an access token.
6. My server reads the user's public profile, finds or creates the user in the database, and issues its own JWT. The GitHub token is discarded.

The `client_secret` is stored in a `.env` file and is never exposed to the browser. Only the `read:user` scope is requested.

## 2. External API

The server calls the free Open-Meteo API (geocoding, then forecast) through `GET /api/weather?city=Chennai`. The browser only talks to my own server. Results are cached for 5 minutes.

## 3. Advanced features

**Rate limiting**

| Route | Limit |
|---|---|
| All `/api` routes | 100 requests per minute |
| `/api/weather` | 10 requests per minute |
| Login and register | 5 failed attempts per minute |

Exceeding a limit returns HTTP 429.

**Error handling**

| Situation | Status |
|---|---|
| Invalid input or invalid JSON | 400 |
| Not logged in or expired token | 401 |
| Not allowed (wrong role or owner) | 403 |
| City or route not found | 404 |
| Too many requests | 429 |
| External service unreachable | 502 |
| External service timed out | 504 |
| Unexpected server error | 500 |

A single central error handler returns clean JSON messages.

## Setup

1. Install Node.js, then run `npm install`.
2. Create a `.env` file in the project folder:
```
   JWT_SECRET=any-long-random-text
   GITHUB_CLIENT_ID=
   GITHUB_CLIENT_SECRET=
```
3. Create a GitHub OAuth App with callback URL `http://localhost:3000/api/auth/github/callback` and put its keys in `.env`.
4. Run `node server.js` and open `http://localhost:3000`.

## Screenshots

See the `screenshots` folder.