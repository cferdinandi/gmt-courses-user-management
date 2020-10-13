<?php

	// Security
	if (!defined('ABSPATH')) exit;


	//
	// Responses
	//

	/**
	 * Return a "domain now allowed" response
	 * @return WP_REST_Response A WP REST API response object
	 */
	function gmt_courses_api_disallowed_response () {
		return new WP_REST_Response(array(
			'code' => 400,
			'status' => 'disallowed_domain',
			'message' => 'This domain is not whitelisted.'
		), 400);
	}

	/**
	 * Return a "not logged in" response
	 * @return WP_REST_Response A WP REST API response object
	 */
	function gmt_courses_api_not_logged_in_response () {
		return new WP_REST_Response(array(
			'code' => 401,
			'status' => 'failed',
			'message' => 'Not logged in.'
		), 401);
	}

	/**
	 * Return an "invalid key" response
	 * @return WP_REST_Response A WP REST API response object
	 */
	function gmt_courses_api_invalid_key_response () {
		return new WP_REST_Response(array(
			'code' => 401,
			'status' => 'failed',
			'message' => 'This password reset link is no longer valid. Please try again. If you keep getting this message, please email ' . gmt_courses_api_get_email() . '.'
		), 401);
	}

	function gmt_courses_api_key_expired_response () {
		return new WP_REST_Response(array(
			'code' => 401,
			'status' => 'failed',
			'message' => 'This password reset link has expired. Please request a new one. If you feel this was in error, please email ' . gmt_courses_api_get_email() . '.'
		), 401);
	}



	//
	// Endpoints
	//

	/**
	 * Log the user in
	 */
	function gmt_courses_api_login ($request) {

		// Get request parameters
		$params = $request->get_params();

		// Check domain whitelist
		if (!gmt_courses_api_is_allowed_domain($request)) {
			return gmt_courses_api_disallowed_response();
		}

		// End existing session, if one exists
		gmt_courses_api_end_session();

		// Make sure account has been validated
		$user = get_user_by('email', $params['username']);
		if (!empty(get_user_meta($user->ID, 'user_validation_key', true))) {
			return new WP_REST_Response(array(
				'code' => 401,
				'status' => 'failed',
				'message' => 'Please validate your account using the link in the email that was sent to you. If you never received a validation link, please email ' . gmt_courses_get_email() . '.'
			), 401);
		}

		// Authenticate User
		$credentials = array(
			'user_login' => $user->user_email,
			'user_password' => $params['password'],
			'remember' => true,
		);
		$login = wp_signon($credentials);
		$session = gmt_courses_api_start_session($user->user_email);

		// If authentication fails
		if (is_wp_error($login) || empty($session)) {
			return new WP_REST_Response(array(
				'code' => 401,
				'status' => 'failed',
				'message' => 'The username or password you provided is not valid.'
			), 401);
		}

		// Send success message
		return new WP_REST_Response(array(
			'code' => 200,
			'status' => 'success',
			'data' => $session['token']
		), 200);

	}

	/**
	 * Log the user out
	 */
	function gmt_courses_api_logout ($request) {

		// Check domain whitelist
		if (!gmt_courses_api_is_allowed_domain($request)) {
			return gmt_courses_api_disallowed_response();
		}

		// Log the user out
		gmt_courses_api_end_session();

		// Send confirmation
		return new WP_REST_Response(array(
			'code' => 200,
			'status' => 'success',
			'message' => 'You have been logged out.'
		), 200);

	}

	/**
	 * Create a new user account
	 */
	function gmt_courses_api_join ($request) {

		// Get request parameters
		$params = $request->get_params();

		// Check domain whitelist
		if (!gmt_courses_api_is_allowed_domain($request)) {
			return gmt_courses_api_disallowed_response();
		}

		// End existing session, if one exists
		gmt_courses_api_end_session();

		// Make sure email address is valid
		$username = sanitize_email($params['username']);
		if ($username !== $params['username']) {
			return new WP_REST_Response(array(
				'code' => 401,
				'status' => 'failed',
				'message' => 'Please use a valid email address.',
			), 401);
		}

		// Get user purchases
		$products = gmt_courses_api_get_user_products($username);

		// If user hasn't made any purchases
		if (empty($products) || (empty($products['guides']) && empty($products['academy']) && empty($products['products']))) {
			return new WP_REST_Response(array(
				'code' => 401,
				'status' => 'failed',
				'message' => 'Please use the same email address that you used to purchase your courses.',
			), 401);
		}

		// If username already exists and is validated
		if (username_exists($username)) {

			// Get validation key
			$user = get_user_by('email', $username);
			$validation = get_user_meta($user->ID, 'user_validation_key', true);

			// If not awaiting validation, throw an error
			if (empty($validation)) {
				return new WP_REST_Response(array(
					'code' => 401,
					'status' => 'failed',
					'message' => 'An account already exists for this email address. If you need to reset your password, please email ' . gmt_courses_api_get_email() . '.'
				), 401);
			}

		}

		// Enforce password security
		$pw_length = getenv('MIN_PASSWORD_LENGTH');
		$pw_length = $pw_length ? intval($pw_length) : 8;
		if (strlen($params['password']) < $pw_length) {
			return new WP_REST_Response(array(
				'code' => 401,
				'status' => 'failed',
				'message' => 'Please use a password that\'s at least ' . $pw_length . ' characters long.'
			), 401);
		}

		// Create new user
		$user = wp_create_user($username, $params['password'], $username);

		// If account creation fails
		if (is_wp_error($user)) {
			return new WP_REST_Response(array(
				'code' => 401,
				'status' => 'failed',
				'message' => 'Something went wrong. Please try again. If you continue to see this message, please email ' . gmt_courses_api_get_email() . '.'
			), 401);
		}

		// Add validation key
		$validation_key =  wp_generate_password(48, false);
		update_user_meta($user, 'user_validation_key', array(
			'key' => $validation_key,
			'expires' => time() + (60 * 60 * 48)
		));

		// Send validation email
		gmt_courses_api_send_validation_email($username, $validation_key);

		return new WP_REST_Response(array(
			'code' => 200,
			'status' => 'success',
			'message' => 'Your account has been created! You were just sent a verification email. Please validate your account within the next 48 hours to complete your registration. If you don\'t receive an email, please email ' . gmt_courses_api_get_email() . '.'
		), 200);

	}

	/**
	 * Validate a new user account
	 */
	function gmt_courses_api_validate ($request) {

		// Get request parameters
		$params = $request->get_params();

		// Check domain whitelist
		if (!gmt_courses_api_is_allowed_domain($request)) {
			return gmt_courses_api_disallowed_response();
		}

		// End existing session, if one exists
		gmt_courses_api_end_session();

		// Variables
		$user = get_user_by('email', $params['username']);
		$validation = get_user_meta($user->ID, 'user_validation_key', true);
		$signup_url = getenv('SIGNUP_URL');

		// If user exists but there's no validation key, let them know account already verified
		if (!empty($user) && empty($validation)) {
			return new WP_REST_Response(array(
				'code' => 401,
				'status' => 'failed',
				'message' => 'This account has already been validated. <a href="/">Please login</a> to access your courses. If you don\'t know your password or feel this is an error, please email ' . gmt_courses_api_get_email() . '.'
			), 401);
		}

		// If validation fails
		if (empty($user) || empty($validation) || strcmp($params['key'], $validation['key']) !== 0) {
			return new WP_REST_Response(array(
				'code' => 401,
				'status' => 'failed',
				'message' => 'This validation link is not valid. If you feel this was in error, please email ' . gmt_courses_api_get_email() . '.'
			), 401);
		}

		// If validation key has expired, ask them to try again
		if (time() > $validation['expires']) {
			return new WP_REST_Response(array(
				'code' => 401,
				'status' => 'failed',
				'message' => 'This validation link has expired. Please <a href="' . $signup_url . '">try creating an account again</a>. If you feel this was in error, please email ' . gmt_courses_api_get_email() . '.'
			), 401);
		}

		// Remove the validation key
		delete_user_meta($user->ID, 'user_validation_key');

		// Send success data
		return new WP_REST_Response(array(
			'code' => 200,
			'status' => 'success',
			'message' => 'Your account was successfully validated. <a href="/">Please login</a> to access your courses.'
		), 200);

	}

	/**
	 * Change a user's password
	 */
	function gmt_courses_api_password_change ($request) {

		// Get request parameters
		$params = $request->get_params();

		// Check domain whitelist
		if (!gmt_courses_api_is_allowed_domain($request)) {
			return gmt_courses_api_disallowed_response();
		}

		// Make sure the user is logged in
		if (!gmt_courses_api_is_authenticated($params['token'])) {
			return gmt_courses_api_not_logged_in_response();
		}

		// Check that current password is supplied
		if (empty($params['current_password'])) {
			return new WP_REST_Response(array(
				'code' => 401,
				'status' => 'failed',
				'message' => 'Please enter your current password.'
			), 401);
		}

		// Check that new password is provided
		if (empty($params['new_password'])) {
			return new WP_REST_Response(array(
				'code' => 401,
				'status' => 'failed',
				'message' => 'Please enter a new password.'
			), 401);
		}

		// Get the current user
		$email = gmt_courses_api_get_user();
		$current_user = get_user_by('email', $email);

		// Validate and authenticate current password
		if (!wp_check_password($params['current_password'], $current_user->user_pass, $current_user->ID)) {
			return new WP_REST_Response(array(
				'code' => 401,
				'status' => 'failed',
				'message' => 'The password you provided is incorrect.'
			), 401);
		}

		// Enforce password requirements
		$pw_length = getenv('MIN_PASSWORD_LENGTH');
		$pw_length = $pw_length ? intval($pw_length) : 8;
		if (strlen($params['new_password']) < $pw_length) {
			return new WP_REST_Response(array(
				'code' => 401,
				'status' => 'failed',
				'message' => 'Please enter a new password that\'s at least ' . $pw_length . ' characters long.'
			), 401);
		}

		// Update the password
		$update = wp_update_user(array('ID' => $current_user->ID, 'user_pass' => $params['new_password']));

		// If update fails
		if (is_wp_error($update)) {
			return new WP_REST_Response(array(
				'code' => 401,
				'status' => 'failed',
				'message' => 'Something went wrong. Please try again. If you continue to see this message, please email ' . gmt_courses_get_email() . '.'
			), 401);
		}

		// Success!
		return new WP_REST_Response(array(
			'code' => 200,
			'status' => 'success',
			'message' => 'Your password has been updated.'
		), 200);

	}

	/**
	 *Send a lost password email
	 */
	function gmt_courses_api_password_lost ($request) {

		// Get request parameters
		$params = $request->get_params();

		// Check domain whitelist
		if (!gmt_courses_api_is_allowed_domain($request)) {
			return gmt_courses_api_disallowed_response();
		}

		// End existing session, if one exists
		gmt_courses_api_end_session();

		// Make sure the user exists
		$user = get_user_by('email', $params['username']);
		if (empty($user)) {
			return new WP_REST_Response(array(
				'code' => 401,
				'status' => 'failed',
				'message' => 'Please enter the email address associated with your account. If you don\'t remember what it is, please email ' . gmt_courses_api_get_email() . '.'
			), 401);
		}

		// Add reset validation key
		$reset_key =  wp_generate_password(48, false);
		update_user_meta($user->ID, 'password_reset_key', array(
			'key' => $reset_key,
			'expires' => time() + (60 * 60 * 48)
		));

		// Send reset email
		gmt_courses_api_send_pw_reset_email($params['username'], $reset_key);

		return new WP_REST_Response(array(
			'code' => 200,
			'status' => 'success',
			'message' => 'A link to reset your password has been sent to ' . $params['username'] . '. Please reset your password within the next 48 hours. If you don\'t receive an email, please email ' . gmt_courses_api_get_email() . '.'
		), 200);

	}

	/**
	 * Validate password reset key
	 */
	function gmt_courses_api_password_validate_key ($request) {

		// Get request parameters
		$params = $request->get_params();

		// Check domain whitelist
		if (!gmt_courses_api_is_allowed_domain($request)) {
			return gmt_courses_api_disallowed_response();
		}

		// End existing session, if one exists
		gmt_courses_api_end_session();

		// Variables
		$user = get_user_by('email', $params['username']);
		$reset_key = get_user_meta($user->ID, 'password_reset_key', true);

		// If user exists but there's no reset key, or the reset key has expired, have the user try again
		if (!gmt_courses_api_is_reset_key($user, $params['key'], $reset_key['key'])) {
			return gmt_courses_api_invalid_key_response();
		}

		// If reset key has expired, ask them to try again
		if (gmt_courses_api_has_key_expired($reset_key['expires'])) {
			return gmt_courses_api_key_expired_response();
		}

		// Otherwise, reset key is valid
		return new WP_REST_Response(array(
			'code' => 200,
			'status' => 'success'
		), 200);

	}

	/**
	 * Reset a lost password
	 */
	function gmt_courses_api_password_reset ($request) {

		// Get request parameters
		$params = $request->get_params();

		// Check domain whitelist
		if (!gmt_courses_api_is_allowed_domain($request)) {
			return gmt_courses_api_disallowed_response();
		}

		// End existing session, if one exists
		gmt_courses_api_end_session();

		// Variables
		$user = get_user_by('email', $params['username']);
		$reset_key = get_user_meta($user->ID, 'password_reset_key', true);
		$reset_pw_url = getenv('RESET_PW_URL');
		$frontend_url = getenv('FRONTEND_URL');

		// If user exists but there's no reset key, or the reset key has expired, have the user try again
		if (!gmt_courses_api_is_reset_key($user, $params['key'], $reset_key['key'])) {
			return gmt_courses_api_invalid_key_response();
		}

		// If reset key has expired, ask them to try again
		if (gmt_courses_api_has_key_expired($reset_key['expires'])) {
			return gmt_courses_api_key_expired_response();
		}

		// Check that password is supplied
		if (empty($params['password'])) {
			return new WP_REST_Response(array(
				'code' => 401,
				'status' => 'failed',
				'message' => 'Please enter a new password.'
			), 401);
		}

		// Enforce password requirements
		$pw_length = getenv('MIN_PASSWORD_LENGTH');
		$pw_length = $pw_length ? intval($pw_length) : 8;
		if (strlen($params['password']) < $pw_length) {
			return new WP_REST_Response(array(
				'code' => 401,
				'status' => 'failed',
				'message' => 'Please enter a new password that\'s at least ' . $pw_length . ' characters long.'
			), 401);
		}

		// Update the password
		$update = wp_update_user(array('ID' => $user->ID, 'user_pass' => $params['password']));

		// If update fails
		if (is_wp_error($update)) {
			return new WP_REST_Response(array(
				'code' => 401,
				'status' => 'failed',
				'message' => 'Something went wrong. Please try again. If you continue to see this message, please email ' . gmt_courses_api_get_email() . '.'
			), 401);
		}

		// Remove the validation key
		delete_user_meta($user->ID, 'password_reset_key');

		// Authenticate User
		$credentials = array(
			'user_login' => $params['username'],
			'user_password' => $params['password'],
			'remember' => true,
		);
		$login = wp_signon($credentials);

		// If authentication fails
		if (is_wp_error($login)) {
			return new WP_REST_Response(array(
				'code' => 205,
				'status' => 'success',
				'message' => 'Your password was successfully reset.' . (empty($frontend_url) ? '' : ' <a href="' . $frontend_url . '">Sign in with your new password</a> to view your courses.')
			), 205);
		}

		// Send success data
		return new WP_REST_Response(array(
			'code' => 200,
			'status' => 'success',
			'message' => 'Your password was successfully reset.' . (empty($frontend_url) ? '' : ' <a href="' . $frontend_url . '">Click here to view your courses.</a>')
		), 200);

	}

	/**
	 * Get the courses an already logged in user has access to
	 */
	function gmt_courses_api_get_products ($request) {

		// Get request parameters
		$params = $request->get_params();

		// Check domain whitelist
		if (!gmt_courses_api_is_allowed_domain($request)) {
			return gmt_courses_api_disallowed_response();
		}

		// Make sure the user is logged in
		if (!gmt_courses_api_is_authenticated($params['token'])) {
			return gmt_courses_api_not_logged_in_response();
		}

		// Get user purchases
		$email = gmt_courses_api_get_user();
		$products = gmt_courses_api_get_user_products($email);

		// Send data back
		return new WP_REST_Response(array(
			'code' => 200,
			'status' => 'success',
			'data' => array(
				'email' => $email,
				'products' => $products
			)
		), 200);

	}

	/**
	 * Get the lessons or assets for a specific product
	 */
	function gmt_courses_api_get_product ($request) {

		// Get request parameters
		$params = $request->get_params();

		// Check domain whitelist
		if (!gmt_courses_api_is_allowed_domain($request)) {
			return gmt_courses_api_disallowed_response();
		}

		// Make sure the user is logged in
		if (!gmt_courses_api_is_authenticated($params['token'])) {
			return gmt_courses_api_not_logged_in_response();
		}

		// Get user data
		$email = gmt_courses_api_get_user();

		// Send data back
		return new WP_REST_Response(array(
			'code' => 200,
			'status' => 'success',
			'data' => gmt_courses_api_get_user_product($email, $params['id'], $params['type'])
		), 200);

	}



	//
	// Setup
	//

	function gmt_courses_api_register_routes () {

		// // Check if the user is logged in
		// register_rest_route('gmt-courses/v1', '/is-logged-in', array(
		// 	'methods' => 'GET',
		// 	'callback' => 'gmt_courses_api_is_logged_in'
		// ));

		// Log a user in
		register_rest_route('gmt-courses/v1', '/login', array(
			'methods' => 'POST',
			'callback' => 'gmt_courses_api_login'
		));

		// Log the current user out
		register_rest_route('gmt-courses/v1', '/logout', array(
			'methods' => 'POST',
			'callback' => 'gmt_courses_api_logout'
		));

		// Create a new user
		register_rest_route('gmt-courses/v1', '/join', array(
			'methods' => 'POST',
			'callback' => 'gmt_courses_api_join'
		));

		// Validate a new user account
		register_rest_route('gmt-courses/v1', '/validate', array(
			'methods' => 'POST',
			'callback' => 'gmt_courses_api_validate'
		));

		// Change a user's password
		register_rest_route('gmt-courses/v1', '/password-change', array(
			'methods' => 'POST',
			'callback' => 'gmt_courses_api_password_change'
		));

		// Send lost password email
		register_rest_route('gmt-courses/v1', '/password-lost', array(
			'methods' => 'GET',
			'callback' => 'gmt_courses_api_password_lost'
		));

		// Send lost password email
		register_rest_route('gmt-courses/v1', '/password-validate-key', array(
			'methods' => 'POST',
			'callback' => 'gmt_courses_api_password_validate_key'
		));

		// Reset lost password
		register_rest_route('gmt-courses/v1', '/password-reset', array(
			'methods' => 'POST',
			'callback' => 'gmt_courses_api_password_reset'
		));

		// Get the current user's purchases
		register_rest_route('gmt-courses/v1', '/purchases', array(
			'methods' => 'GET',
			'callback' => 'gmt_courses_api_get_products'
		));

		// Get data for a specific purchase
		register_rest_route('gmt-courses/v1', '/purchase', array(
			'methods' => 'GET',
			'callback' => 'gmt_courses_api_get_product'
		));

	}
	add_action('rest_api_init', 'gmt_courses_api_register_routes');