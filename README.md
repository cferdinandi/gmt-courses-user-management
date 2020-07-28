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

## New API

This API uses `<your-domain>/gmt-courses/v1` as the root for all endpoints.

### Endpoints

| Endpoint                 | Description                                   | Method | Parameters                         |
|--------------------------|-----------------------------------------------|--------|------------------------------------|
| `/login`                 | Sign a user in                                | `POST` | `username`, `password`             |
| `/logout`                | Log a user out                                | `POST` |                                    |
| `/join`                  | Create a new user                             | `POST` | `username`, `password`             |
| `/validate`              | Validate a user account                       | `POST` | `username`, `key`                  |
| `/password-change`       | Change a user password                        | `POST` | `current_password`, `new_password` |
| `/password-lost`         | Send a password reset email                   | `GET`  | `username`                         |
| `/password-validate-key` | Validate a password reset key                 | `POST` | `username`, `key`                  |
| `/password-reset`        | Reset a password                              | `POST` | `username`, `key`, `password`      |
| `/purchases`             | Get a user's purchases                        | `GET`  |                                    |
| `/purchase`              | Get lessons or assets for a specific purchase | `GET`  | `id`, `type`                       |


## Legacy API

The legacy WP Ajax API is being deprecated in favor a new approach that uses the WP REST API.

This is a transitional release that will allow you to maintain apps that use both new and legacy approaches. The next major release will fully remove the legacy API.

### Ajax Call

```js
atomic.ajax({
	type: 'POST',
	url: baseURL + '/wp-admin/admin-ajax.php',
	headers: {
		'X-Requested-With': 'XMLHttpRequest'
},
	data: {
		action: 'action',
	}
}).success(function (data, xhr) {
	console.log(data);
});
```

### Actions

- `gmt_courses_is_logged_in` - Check if the current user is logged in.
- `gmt_courses_get_products` - Get purchased products for a logged in user.
- `gmt_courses_get_product` - Get details for a specific product a user has purchased.
- `gmt_courses_get_subscriptions` - Get subscription data for a logged in user.
- `gmt_courses_login` - Log a user in.
- `gmt_courses_logout` - Log the current user out.
- `gmt_courses_create_user` - Create a new user.
- `gmt_courses_validate_new_account` - Validate a new user account.
- `gmt_courses_change_password` - Update a user's password.