<?php

	// Security
	if (!defined('ABSPATH')) exit;


	//
	// Responses
	//

	/**
	 * Return an "already logged in" response
	 */
	function gmt_courses_already_logged_in_response () {
		wp_send_json(array(
			'code' => 400,
			'status' => 'loggedin',
			'message' => 'You\'re already logged in.'
		), 400);
	}

	/**
	 * Return a "not logged in" response
	 */
	function gmt_courses_not_logged_in_response () {
		wp_send_json(array(
			'code' => 401,
			'status' => 'failed',
			'message' => 'You are not currently logged in.'
		), 401);
	}

	/**
	 * Return an "invalid key" response
	 */
	function gmt_courses_invalid_key_response () {
		wp_send_json(array(
			'code' => 400,
			'status' => 'failed',
			'message' => 'This password reset link is no longer valid. Please try again. If you keep getting this message, please email ' . gmt_courses_get_email() . '.'
		), 400);
	}

	/**
	 * Return an "expired key" response
	 */
	function gmt_courses_key_expired_response () {
		wp_send_json(array(
			'code' => 400,
			'status' => 'failed',
			'message' => 'This password reset link has expired. Please request a new one. If you feel this was in error, please email ' . gmt_courses_get_email() . '.'
		), 400);
	}

	/**
	 * Return an "insecure password" response
	 */
	function gmt_courses_enforce_password_security_response ($pw) {
		$pw_length = gmt_courses_get_pw_length();
		if (strlen($pw) < $pw_length) {
			wp_send_json(array(
				'code' => 400,
				'status' => 'failed',
				'message' => 'Please enter a new password that\'s at least ' . $pw_length . ' characters long.'
			), 400);
		}
	}

	/**
	 * Return "internal error" response
	 */
	function gmt_courses_internal_error_response () {
		wp_send_json(array(
			'code' => 500,
			'status' => 'failed',
			'message' => 'Something went wrong. Please try again. If you continue to see this message, please email ' . gmt_courses_get_email() . '.'
		), 500);
	}


	//
	// Endpoints
	//

	/**
	 * Check if the user is logged in
	 */
	function gmt_courses_is_logged_in () {

		// Bail if not an Ajax request
		if (gmt_courses_is_not_ajax()) {
			header('Location: ' . $_SERVER['HTTP_REFERER']);
			return;
		}

		// If the user is not logged in
		if (!is_user_logged_in()) {
			gmt_courses_not_logged_in_response();
		}

		// Get the current user's email
		$user = wp_get_current_user();
		wp_send_json(array(
			'code' => 200,
			'status' => 'success',
			'data' => array(
				'email' => $user->user_login,
			)
		), 200);

	}
	add_action('wp_ajax_gmt_courses_is_logged_in', 'gmt_courses_is_logged_in');
	add_action('wp_ajax_nopriv_gmt_courses_is_logged_in', 'gmt_courses_is_logged_in');


	/**
	 * Log the user in via an Ajax call
	 */
	function gmt_courses_login () {

		// Bail if not an Ajax request
		if (gmt_courses_is_not_ajax()) {
			header('Location: ' . $_SERVER['HTTP_REFERER']);
			return;
		}

		// Make sure user isn't already logged in
		if (is_user_logged_in()) {
			gmt_courses_already_logged_in_response();
		}

		// Make sure account has been validated
		$user = get_user_by('email', $_POST['username']);
		if (!empty(get_user_meta($user->ID, 'user_validation_key', true))) {
			wp_send_json(array(
				'code' => 400,
				'status' => 'failed',
				'message' => 'Please validate your account using the link in the email that was sent to you. If you never received a validation link, please email ' . gmt_courses_get_email() . '.'
			), 400);
		}

		// Authenticate User
		$credentials = array(
			'user_login' => $user->user_email,
			'user_password' => $_POST['password'],
			'remember' => true,
		);
		$login = wp_signon($credentials);

		// If authentication fails
		if (is_wp_error($login)) {
			wp_send_json(array(
				'code' => 400,
				'status' => 'failed',
				'message' => 'The username or password you provided is not valid.'
			), 400);
		}

		// Send success message
		wp_send_json(array(
			'code' => 200,
			'status' => 'success',
			'message' => 'The user is logged in.'
		), 200);

	}
	add_action('wp_ajax_gmt_courses_login', 'gmt_courses_login');
	add_action('wp_ajax_nopriv_gmt_courses_login', 'gmt_courses_login');


	/**
	 * Log out the current user via an Ajax request
	 */
	function gmt_courses_logout () {

		// Bail if not an Ajax request
		if (gmt_courses_is_not_ajax()) {
			header('Location: ' . $_SERVER['HTTP_REFERER']);
			return;
		}

		// Log the user out
		wp_logout();

		// Send confirmation
		wp_send_json(array(
			'code' => 200,
			'status' => 'success',
			'message' => 'You have been logged out.'
		), 200);

	}
	add_action('wp_ajax_gmt_courses_logout', 'gmt_courses_logout');
	add_action('wp_ajax_nopriv_gmt_courses_logout', 'gmt_courses_logout');


	/**
	 * Create an account for a new user
	 */
	function gmt_courses_create_user () {

		// Bail if not an Ajax request
		// if (gmt_courses_is_not_ajax()) {
		// 	header('Location: ' . $_SERVER['HTTP_REFERER']);
		// 	return;
		// }

		// Bail if user is already logged in
		// if (is_user_logged_in()) {
		// 	gmt_courses_already_logged_in_response();
		// }

		// Make sure email address is valid
		$username = sanitize_email($_POST['username']);
		if ($username !== $_POST['username']) {
			wp_send_json(array(
				'code' => 400,
				'status' => 'failed',
				'message' => 'Please use a valid email address.',
			), 400);
		}

		// Get user purchases
		$products = gmt_courses_get_user_product_summary($username);

		// If user hasn't made any purchases
		if (empty($products) || (empty($products['guides']) && empty($products['academy']) && empty($products['products']))) {
			wp_send_json(array(
				'code' => 400,
				'status' => 'failed',
				'message' => 'Please use the same email address that you used to purchase your courses.',
			), 400);
		}

		// If username already exists and is validated
		if (username_exists($username)) {

			// Get validation key
			$user = get_user_by('email', $username);
			$validation = get_user_meta($user->ID, 'user_validation_key', true);

			// If not awaiting validation, throw an error
			if (empty($validation)) {
				wp_send_json(array(
					'code' => 400,
					'status' => 'failed',
					'message' => 'An account already exists for this email address. If you need to reset your password, please email ' . gmt_courses_get_email() . '.'
				), 400);
			}

		}

		// Enforce password security
		$pw_length = gmt_courses_get_pw_length();
		if (gmt_courses_is_pw_too_short($_POST['password'], $pw_length)) {
			wp_send_json(array(
				'code' => 400,
				'status' => 'failed',
				'message' => 'Please use a password that\'s at least ' . $pw_length . ' characters long.'
			), 400);
		}

		// Create new user
		if (empty($user)) {

			$user = wp_create_user($username, $_POST['password'], $username);

			// If account creation fails
			if (is_wp_error($user)) {
				gmt_courses_internal_error_response();
			}

		}

		// Add validation key
		$validation_key =  wp_generate_password(48, false);
		update_user_meta($user, 'user_validation_key', array(
			'key' => $validation_key,
			'expires' => time() + (60 * 60 * 48)
		));

		// Send validation email
		gmt_courses_send_validation_email($username, $validation_key);

		// @temp
		$validate_url = getenv('VALIDATE_URL') . '?email=' . $username . '&key=' . $validation_key;

		wp_send_json(array(
			'code' => 200,
			'status' => 'success',
			'message' => 'Your account has been created! You were just sent a verification email. Please validate your account within the next 48 hours to complete your registration. If you don\'t receive an email, please email ' . gmt_courses_get_email() . '.',
			'key' => $validate_url // @temp
		), 200);

	}
	add_action('wp_ajax_gmt_courses_create_user', 'gmt_courses_create_user');
	add_action('wp_ajax_nopriv_gmt_courses_create_user', 'gmt_courses_create_user');


	/**
	 * Validate a new user account
	 */
	function gmt_courses_validate_new_account () {

		// Bail if not an Ajax request
		if (gmt_courses_is_not_ajax()) {
			header('Location: ' . $_SERVER['HTTP_REFERER']);
			return;
		}

		// Bail if user is already logged in
		if (is_user_logged_in()) {
			gmt_courses_already_logged_in_response();
		}

		// Variables
		$user = get_user_by('email', $_POST['username']);
		$validation = get_user_meta($user->ID, 'user_validation_key', true);
		$signup_url = getenv('SIGNUP_URL');

		// If user exists but there's no validation key, let them know account already verified
		if (!empty($user) && empty($validation)) {
			wp_send_json(array(
				'code' => 400,
				'status' => 'failed',
				'message' => 'This account has already been validated. <a href="/">Please login</a> to access your courses. If you don\'t know your password or feel this is an error, please email ' . gmt_courses_get_email() . '.'
			), 400);
		}

		// If validation fails
		if (empty($user) || empty($validation) || strcmp($_POST['key'], $validation['key']) !== 0) {
			wp_send_json(array(
				'code' => 400,
				'status' => 'failed',
				'message' => 'This validation link is not valid. If you feel this was in error, please email ' . gmt_courses_get_email() . '.'
			), 400);
		}

		// If validation key has expired, ask them to try again
		if (time() > $validation['expires']) {
			wp_send_json(array(
				'code' => 400,
				'status' => 'failed',
				'message' => 'This validation link has expired. Please <a href="' . $signup_url . '">try creating an account again</a>. If you feel this was in error, please email ' . gmt_courses_get_email() . '.'
			), 400);
		}

		// Remove the validation key
		delete_user_meta($user->ID, 'user_validation_key');

		// Send success data
		wp_send_json(array(
			'code' => 200,
			'status' => 'success',
			'message' => 'Your account was successfully validated. <a href="/">Please login</a> to access your courses.'
		), 200);

	};
	add_action('wp_ajax_gmt_courses_validate_new_account', 'gmt_courses_validate_new_account');
	add_action('wp_ajax_nopriv_gmt_courses_validate_new_account', 'gmt_courses_validate_new_account');


	/**
	 * Update the user's password
	 */
	function gmt_courses_change_password () {

		// Bail if not an Ajax request
		if (gmt_courses_is_not_ajax()) {
			header('Location: ' . $_SERVER['HTTP_REFERER']);
			return;
		}

		// Bail if user is not logged in
		if (!is_user_logged_in()) {
			gmt_courses_not_logged_in_response();
		}

		// Get the current user
		$current_user = wp_get_current_user();

		// Check that current password is supplied
		if (empty($_POST['current_password'])) {
			wp_send_json(array(
				'code' => 400,
				'status' => 'failed',
				'message' => 'Please enter your current password.'
			), 400);
		}

		// Check that new password is provided
		if (empty($_POST['new_password'])) {
			wp_send_json(array(
				'code' => 400,
				'status' => 'failed',
				'message' => 'Please enter a new password.'
			), 400);
		}

		// Validate and authenticate current password
		if (!wp_check_password($_POST['current_password'], $current_user->user_pass, $current_user->ID)) {
			wp_send_json(array(
				'code' => 400,
				'status' => 'failed',
				'message' => 'The password you provided is incorrect.'
			), 400);
		}

		// Enforce password requirements
		$pw_length = gmt_courses_get_pw_length();
		if (gmt_courses_is_pw_too_short($_POST['new_password'], $pw_length)) {
			wp_send_json(array(
				'code' => 400,
				'status' => 'failed',
				'message' => 'Please enter a new password that\'s at least ' . $pw_length . ' characters long.'
			), 400);
		}

		// Update the password
		$update = wp_update_user(array('ID' => $current_user->ID, 'user_pass' => $_POST['new_password']));

		// If update fails
		if (is_wp_error($update)) {
			gmt_courses_internal_error_response();
		}

		// Success!
		wp_send_json(array(
			'code' => 200,
			'status' => 'success',
			'message' => 'Your password has been updated.'
		), 200);

	}
	add_action('wp_ajax_gmt_courses_change_password', 'gmt_courses_change_password');
	add_action('wp_ajax_nopriv_gmt_courses_change_password', 'gmt_courses_change_password');


	/**
	 * Send a "lost password" reset email
	 */
	function gmt_courses_lost_password () {

		// Bail if not an Ajax request
		if (gmt_courses_is_not_ajax()) {
			header('Location: ' . $_SERVER['HTTP_REFERER']);
			return;
		}

		// Bail if user is already logged in
		if (is_user_logged_in()) {
			gmt_courses_already_logged_in_response();
		}

		// Make sure the user exists
		$user = get_user_by('email', $_POST['username']);
		if (empty($user)) {
			wp_send_json(array(
				'code' => 400,
				'status' => 'failed',
				'message' => 'Please enter the email address associated with your account. If you don\'t remember what it is, please email ' . gmt_courses_get_email() . '.'
			), 400);
		}

		// Add reset validation key
		$reset_key =  wp_generate_password(48, false);
		update_user_meta($user->ID, 'password_reset_key', array(
			'key' => $reset_key,
			'expires' => time() + (60 * 60 * 48)
		));

		// Send reset email
		gmt_courses_send_pw_reset_email($_POST['username'], $reset_key);

		wp_send_json(array(
			'code' => 200,
			'status' => 'success',
			'message' => 'A link to reset your password has been sent to ' . $_POST['username'] . '. Please reset your password within the next 48 hours. If you don\'t receive an email, please email ' . gmt_courses_get_email() . '.'
		), 200);

	}
	add_action('wp_ajax_gmt_courses_lost_password', 'gmt_courses_lost_password');
	add_action('wp_ajax_nopriv_gmt_courses_lost_password', 'gmt_courses_lost_password');


	/**
	 * Check if the provided reset key is valid
	 */
	function gmt_courses_is_reset_key_valid () {

		// Bail if not an Ajax request
		if (gmt_courses_is_not_ajax()) {
			header('Location: ' . $_SERVER['HTTP_REFERER']);
			return;
		}

		// Bail if user is already logged in
		if (is_user_logged_in()) {
			gmt_courses_already_logged_in_response();
		}

		// Variables
		$user = get_user_by('email', $_POST['username']);
		$reset_key = get_user_meta($user->ID, 'password_reset_key', true);

		// If user exists but there's no reset key, or the reset key has expired, have the user try again
		if (empty($user) || empty($reset_key) || strcmp($_POST['key'], $reset_key['key']) !== 0) {
			gmt_courses_invalid_key_response();
		}

		// If reset key has expired, ask them to try again
		if (gmt_courses_has_reset_key_expired($reset_key)) {
			gmt_courses_key_expired_response();
		}

		// Otherwise, reset key is valid
		wp_send_json(array(
			'code' => 200,
			'status' => 'success'
		), 200);

	}
	add_action('wp_ajax_gmt_courses_is_reset_key_valid', 'gmt_courses_is_reset_key_valid');
	add_action('wp_ajax_nopriv_gmt_courses_is_reset_key_valid', 'gmt_courses_is_reset_key_valid');


	/**
	 * Reset a user's password
	 */
	function gmt_courses_reset_password () {

		// Bail if not an Ajax request
		if (gmt_courses_is_not_ajax()) {
			header('Location: ' . $_SERVER['HTTP_REFERER']);
			return;
		}

		// Bail if user is already logged in
		if (is_user_logged_in()) {
			gmt_courses_already_logged_in_response();
		}

		// Variables
		$user = get_user_by('email', $_POST['username']);
		$reset_key = get_user_meta($user->ID, 'password_reset_key', true);
		$reset_pw_url = getenv('RESET_PW_URL');
		$frontend_url = getenv('FRONTEND_URL');

		// If user exists but there's no reset key, or the reset key has expired, have the user try again
		if (empty($user) || empty($reset_key) || strcmp($_POST['key'], $reset_key['key']) !== 0) {
			gmt_courses_invalid_key_response();
		}

		// If reset key has expired, ask them to try again
		if (gmt_courses_has_reset_key_expired($reset_key)) {
			gmt_courses_key_expired_response();
		}

		// Check that password is supplied
		if (empty($_POST['password'])) {
			wp_send_json(array(
				'code' => 400,
				'status' => 'failed',
				'message' => 'Please enter a new password.'
			), 400);
		}

		// Enforce password requirements
		$pw_length = gmt_courses_get_pw_length();
		if (strlen($_POST['password']) < $pw_length) {
			wp_send_json(array(
				'code' => 400,
				'status' => 'failed',
				'message' => 'Please enter a new password that\'s at least ' . $pw_length . ' characters long.'
			), 400);
		}

		// Update the password
		$update = wp_update_user(array('ID' => $user->ID, 'user_pass' => $_POST['password']));

		// If update fails
		if (is_wp_error($update)) {
			gmt_courses_internal_error_response();
		}

		// Remove the validation key
		delete_user_meta($user->ID, 'password_reset_key');

		// Authenticate User
		$credentials = array(
			'user_login' => $_POST['username'],
			'user_password' => $_POST['password'],
			'remember' => true,
		);
		$login = wp_signon($credentials);

		// If authentication fails
		if (is_wp_error($login)) {
			wp_send_json(array(
				'code' => 205,
				'status' => 'success',
				'message' => 'Your password was successfully reset.' . (empty($frontend_url) ? '' : ' <a href="' . $frontend_url . '">Sign in with your new password</a> to view your courses.')
			), 205);
		}

		// Send success data
		wp_send_json(array(
			'code' => 200,
			'status' => 'success',
			'message' => 'Your password was successfully reset.' . (empty($frontend_url) ? '' : ' <a href="' . $frontend_url . '">Click here to view your courses.</a>')
		), 200);

	}
	add_action('wp_ajax_gmt_courses_reset_password', 'gmt_courses_reset_password');
	add_action('wp_ajax_nopriv_gmt_courses_reset_password', 'gmt_courses_reset_password');


	/**
	 * Get the details for a course for a logged in user
	 */
	function gmt_courses_get_product_data () {

		// If user isn't logged in, return error
		if (!is_user_logged_in()) {
			gmt_courses_not_logged_in_response();
		}

		// Get endpoint
		$api = $_GET['api'];
		$type = $_GET['type'];
		if (empty($api) || empty($type)) {
			wp_send_json(array(
				'code' => 400,
				'status' => 'bad_request',
				'message' => 'Something went wrong. Please email ' . gmt_courses_get_email() . '.'
			), 400);
		}

		// Get user purchases
		$user = wp_get_current_user();
		$product = ($api === 'summary' ? gmt_courses_get_user_product_summary($user->user_email) : gmt_courses_get_user_product_details($user->user_email, $type, $api));

		// If there are no products, show an error
		if (empty($product)) {
			wp_send_json(array(
				'code' => 403,
				'status' => 'no_access',
				'message' => 'You don\'t have access to this content. Sorry!',
				'product' => $product,
			), 403);
		}

		// Send data back
		wp_send_json(array(
			'code' => 200,
			'status' => 'success',
			'email' => $api === 'summary' ? $user->user_email : null,
			'data' => $product
		), 200);

	}


	/**
	 * Send user a Slack invite
	 */
	function gmt_courses_slack () {

		// If user isn't logged in, return error
		if (!is_user_logged_in()) {
			gmt_courses_not_logged_in_response();
		}

		// Get Slack credentials
		$slack_team = getenv('SLACK_TEAM');
		$slack_token = getenv('SLACK_TOKEN');

		// If there are no Slack credentials, error
		if (empty($slack_team) || empty($slack_token)) {
			gmt_courses_internal_error_response();
		}

		// Get the current user
		$current_user = wp_get_current_user();
		$email = $current_user->user_email;

		// Limit to valid EDD purchases only
		// @TODO write logic

		// Get the channels to add user to
		// @TODO
		$channels = array('channels' => '<comma-separated string>');

		// Invite purchaser to Slack
		$slack = new Slack_Invite($slack_token, $slack_team);
		$invitation = $slack->send_invite($email, $channels);

		// If invite a success
		if ($invitation['ok'] === TRUE) {
			wp_send_json(array(
				'code' => 200,
				'status' => 'success',
				'message' => 'An invitation to join the Slack workspace has been sent.'
			), 200);
		}

		// If an invite was already sent
		if ($invitation['error'] === 'already_invited') {
			wp_send_json(array(
				'code' => 400,
				'status' => 'already_invited',
				'message' => 'You\'ve already been sent an invite. If you didn\'t receive it, please contact the workspace administrator.'
			), 400);
		}

		// If the user is already in the team, add to new channels
		if ($invitation['error'] === 'already_in_team') {
			if (!empty($channels)) {
				$channels = explode(',', $channels['channels']);
				$member = $slack->get_member($email);
				$added_to_channels = false;
				foreach ($channels as $channel) {
					$add = $slack->add_to_group($member, $channel);
					if ($add['ok'] === TRUE) {
						$added_to_channels = true;
					}
				}

				// If they were added to at least one new channel
				if ($added_to_channels === TRUE) {
					wp_send_json(array(
						'code' => 200,
						'status' => 'new_channel',
						'message' => 'You have been added to a new channel in this workspace.'
					), 200);
				}
			}

			// Otherwise, throw an error
			wp_send_json(array(
				'code' => 400,
				'status' => 'already_in_team',
				'message' => 'You\'re already a member of this Slack workspace.'
			), 400);
		}

		// Catchall error
		wp_send_json(array(
			'code' => 500,
			'status' => 'failed',
			'message' => 'Unable to subscribe at this time. Please try again.'
		), 500);

	}
	add_action('wp_ajax_gmt_courses_slack', 'gmt_courses_slack');
	add_action('wp_ajax_nopriv_gmt_courses_slack', 'gmt_courses_slack');


	/**
	 * Add a custom product feed
	 * This adds a feed http://example.com/?feed=myfeed
	 */
	function gmt_courses_add_product_feed () {
	    add_feed('gmt-products', 'gmt_courses_get_products'); // @deprecated
	    add_feed('gmt-product-data', 'gmt_courses_get_product_data');
	}
	add_action('init', 'gmt_courses_add_product_feed');
