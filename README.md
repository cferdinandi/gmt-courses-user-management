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

## WP REST API Endpoints

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


## Endpoints

Endpoint use [the WP Ajax endpoint](https://developer.wordpress.org/reference/hooks/wp_ajax_action/) with `action` hooks.

### Example JavaScript Call

```js
fetch('/wp-admin/admin-ajax.php', {
	method: 'POST',
	headers: {
		'X-Requested-With': 'XMLHttpRequest',
		'Content-type': 'application/x-www-form-urlencoded'
	},
	body: 'action={ACTION_TYPE}'
}).then(function (response) {
	if (response.ok) {
		return response.json();
	}
	throw new Error(response);
}).then(function (data) {

	// Response data
	console.log(data);

}).catch(function (error) {

	// Error
	console.warn(error);

});
```

### Actions

- `gmt_courses_is_logged_in` - Check if the current user is logged in.
- `gmt_courses_get_products` - Get purchased products for a logged in user. // @todo
- `gmt_courses_login` - Log a user in.
- `gmt_courses_logout` - Log the current user out.
- `gmt_courses_create_user` - Create a new user.
- `gmt_courses_validate_new_account` - Validate a new user account.
- `gmt_courses_change_password` - Update a user's password.
- `gmt_courses_lost_password` - Send a lost password reset email.
- `gmt_courses_reset_password` - Reset a lost password.
- `gmt_courses_is_reset_key_valid` - Check if a reset key is valid.