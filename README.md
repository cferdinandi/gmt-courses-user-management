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
```

## Ajax Call

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

## Actions

- `gmt_courses_is_logged_in` - Check if the current user is logged in.
- `gmt_courses_get_courses` - Get course data for a logged in user.
- `gmt_courses_login` - Log a user in.
- `gmt_courses_logout` - Log the current user out.
- `gmt_courses_create_user` - Create a new user.
- `gmt_courses_validate_new_account` - Validate a new user account.
- `gmt_courses_change_password` - Update a user's password.