# GMT Courses User Management
User processes for GMT Courses.

## Required Environment Variables

```bash
SetEnv CHECKOUT_URL <url-for-checkout-page>
SetEnv CHECKOUT_USERNAME <basic-auth-username>
SetEnv CHECKOUT_PW <basic-auth-password>
SetEnv COURSE_DATA <course-data-filename>
SetEnv SIGNUP_URL <url-for-signup-page>
SetEnv VALIDATE_URL <url-for-user-validation-page>
SetEnv MIN_PASSWORD_LENGTH <min-password-length>
SetEnv RESET_PW_URL <url-for-password-reset-form>
SetEnv FRONTEND_URL <url-for-the-frontend> # if you want to redirect users away
SetEnv API_ORIGINS <url-for-whitelist-origin>
```

## Endpoints

The `login` endpoint returns a session token that needs to be used for any authenticated requests.

| Endpoint                 | Description                                   | Method | Parameters                                  |
|--------------------------|-----------------------------------------------|--------|---------------------------------------------|
| `/login`                 | Sign a user in                                | `POST` | `username`, `password`                      |
| `/logout`                | Log a user out                                | `POST` |                                             |
| `/join`                  | Create a new user                             | `POST` | `username`, `password`                      |
| `/validate`              | Validate a user account                       | `POST` | `username`, `key`                           |
| `/password-change`       | Change a user password                        | `POST` | `current_password`, `new_password`, `token` |
| `/password-lost`         | Send a password reset email                   | `GET`  | `username`                                  |
| `/password-validate-key` | Validate a password reset key                 | `POST` | `username`, `key`                           |
| `/password-reset`        | Reset a password                              | `POST` | `username`, `key`, `password`               |
| `/purchases`             | Get a user's purchases                        | `GET`  | `token`                                     |
| `/purchase`              | Get lessons or assets for a specific purchase | `GET`  | `id`, `type`, `token`                       |
