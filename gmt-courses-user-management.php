<?php

/**
 * Plugin Name: GMT Courses User Management
 * Plugin URI: https://github.com/cferdinandi/gmt-courses-user-management/
 * GitHub Plugin URI: https://github.com/cferdinandi/gmt-courses-user-management/
 * Description: User processes for GMT Courses.
 * Version: 0.0.5
 * Author: Chris Ferdinandi
 * Author URI: http://gomakethings.com
 * License: GPLv3
 *
 * Notes and references:
 * - https://codex.wordpress.org/Function_Reference/wp_send_json
 * - https://codex.wordpress.org/AJAX_in_Plugins
 * - https://www.smashingmagazine.com/2011/10/how-to-use-ajax-in-wordpress/
 */


	//
	// AJAX Methods
	//

	/**
	 * Check if the user is logged in
	 */
	function gmt_courses_is_logged_in () {

		// Bail if not an Ajax request
		if (empty($_SERVER['HTTP_X_REQUESTED_WITH']) || strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) !== 'xmlhttprequest') {
			header('Location: ' . $_SERVER['HTTP_REFERER']);
			return;
		}

		// If the user is not logged in
		if (!is_user_logged_in()) {
			wp_send_json(array(
				'code' => 401,
				'status' => 'failed',
				'message' => 'Not logged in.'
			));
		}

		// Get the current user's email
		$user = wp_get_current_user();
		wp_send_json(array(
			'code' => 200,
			'status' => 'success',
			'data' => array(
				'email' => $user->user_email
			)
		));

	}
	add_action('wp_ajax_gmt_courses_is_logged_in', 'gmt_courses_is_logged_in');
	add_action('wp_ajax_nopriv_gmt_courses_is_logged_in', 'gmt_courses_is_logged_in');


	/**
	 * Get the courses an already logged in user has access to
	 */
	function gmt_courses_get_courses () {

		// Bail if not an Ajax request
		if (empty($_SERVER['HTTP_X_REQUESTED_WITH']) || strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) !== 'xmlhttprequest') {
			header('Location: ' . $_SERVER['HTTP_REFERER']);
			return;
		}

		if (!is_user_logged_in()) {
			wp_send_json(array(
				'code' => 401,
				'status' => 'failed',
				'message' => 'You\'re not logged in yet.'
			));
		}

		// Get user purchases
		$user = wp_get_current_user();
		$courses = gmt_courses_get_user_courses($user->user_email);

		// Send data back
		wp_send_json(array(
			'code' => 200,
			'status' => 'success',
			'data' => array(
				'email' => $user->user_email,
				'data' => $courses
			)
		));

	}
	add_action('wp_ajax_gmt_courses_get_courses', 'gmt_courses_get_courses');
	add_action('wp_ajax_nopriv_gmt_courses_get_courses', 'gmt_courses_get_courses');


	/**
	 * Log the user in via an Ajax call
	 * @return JSON The user's course data
	 */
	function gmt_courses_login () {

		// Bail if not an Ajax request
		if (empty($_SERVER['HTTP_X_REQUESTED_WITH']) || strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) !== 'xmlhttprequest') {
			header('Location: ' . $_SERVER['HTTP_REFERER']);
			return;
		}

		// Make sure user isn't already logged in
		if (is_user_logged_in()) {
			wp_send_json(array(
				'code' => 401,
				'status' => 'failed',
				'message' => 'You\'re already logged in.'
			));
		}

		// Make sure account has been validated
		$user = get_user_by('email', $_POST['username']);
		if (!empty(get_user_meta($user->ID, 'user_validation_key', true))) {
			wp_send_json(array(
				'code' => 401,
				'status' => 'failed',
				'message' => 'Please validate your account using the link in the email that was sent to you. If you never received a validation link, please email <a href="mailto:&#099;&#104;&#114;&#105;&#115;&#064;&#103;&#111;&#109;&#097;&#107;&#101;&#116;&#104;&#105;&#110;&#103;&#115;&#046;&#099;&#111;&#109;">&#099;&#104;&#114;&#105;&#115;&#064;&#103;&#111;&#109;&#097;&#107;&#101;&#116;&#104;&#105;&#110;&#103;&#115;&#046;&#099;&#111;&#109;</a>.'
			));
		}

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
				'code' => 401,
				'status' => 'failed',
				'message' => 'The username or password you provided is not valid.'
			));
		}

		// Send success message
		wp_send_json(array(
			'code' => 200,
			'status' => 'success',
			'message' => 'The user is logged in.'
		));

	}
	add_action('wp_ajax_gmt_courses_login', 'gmt_courses_login');
	add_action('wp_ajax_nopriv_gmt_courses_login', 'gmt_courses_login');


	/**
	 * Log out the current user via an Ajax request
	 */
	function gmt_courses_logout () {

		// Bail if not an Ajax request
		if (empty($_SERVER['HTTP_X_REQUESTED_WITH']) || strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) !== 'xmlhttprequest') {
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
		));

	}
	add_action('wp_ajax_gmt_courses_logout', 'gmt_courses_logout');
	add_action('wp_ajax_nopriv_gmt_courses_logout', 'gmt_courses_logout');


	/**
	 * Create an account for a new user
	 */
	function gmt_courses_create_user () {

		// Bail if not an Ajax request
		if (empty($_SERVER['HTTP_X_REQUESTED_WITH']) || strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) !== 'xmlhttprequest') {
			header('Location: ' . $_SERVER['HTTP_REFERER']);
			return;
		}

		// Bail if user is already logged in
		if (is_user_logged_in()) {
			wp_send_json(array(
				'code' => 401,
				'status' => 'failed',
				'message' => 'You\'re already logged in.'
			));
		}

		// Get user purchases
		$courses = gmt_courses_get_user_courses($_POST['username']);

		// If user hasn't made any purchases
		if (empty($courses) || empty($courses->courses) || !filter_var($_POST['username'], FILTER_VALIDATE_EMAIL) || !validate_username($_POST['username'])) {
			wp_send_json(array(
				'code' => 401,
				'status' => 'failed',
				'message' => 'Please use the same email address that you used to purchase your courses.'
			));
		}

		// If username already exists
		if (username_exists($_POST['username'])) {
			wp_send_json(array(
				'code' => 401,
				'status' => 'failed',
				'message' => 'An account already exists for this email address. If you need to reset your password, please email <a href="mailto:&#099;&#104;&#114;&#105;&#115;&#064;&#103;&#111;&#109;&#097;&#107;&#101;&#116;&#104;&#105;&#110;&#103;&#115;&#046;&#099;&#111;&#109;">&#099;&#104;&#114;&#105;&#115;&#064;&#103;&#111;&#109;&#097;&#107;&#101;&#116;&#104;&#105;&#110;&#103;&#115;&#046;&#099;&#111;&#109;</a>.'
			));
		}

		// Enforce password security
		$pw_length = getenv('MIN_PASSWORD_LENGTH');
		$pw_length = $pw_length ? intval($pw_length) : 8;
		if (strlen($_POST['password']) < $pw_length) {
			wp_send_json(array(
				'code' => 401,
				'status' => 'failed',
				'message' => 'Please use a password that\'s at least ' . $pw_length . ' characters long.'
			));
		}

		// Create new user
		$user = wp_create_user(sanitize_email($_POST['username']), $_POST['password'], sanitize_email($_POST['username']));

		// If account creation fails
		if (is_wp_error($user)) {
			wp_send_json(array(
				'code' => 401,
				'status' => 'failed',
				'message' => 'Something went wrong. Please try again. If you continue to see this message, please email <a href="mailto:&#099;&#104;&#114;&#105;&#115;&#064;&#103;&#111;&#109;&#097;&#107;&#101;&#116;&#104;&#105;&#110;&#103;&#115;&#046;&#099;&#111;&#109;">&#099;&#104;&#114;&#105;&#115;&#064;&#103;&#111;&#109;&#097;&#107;&#101;&#116;&#104;&#105;&#110;&#103;&#115;&#046;&#099;&#111;&#109;</a>.'
			));
		}

		// Add validation key
		$validation_key =  wp_generate_password(48, false);
		update_user_meta($user, 'user_validation_key', array(
			'key' => $validation_key,
			'expires' => time() + (60 * 60 * 48)
		));

		// Send validation email
		gmt_courses_send_validation_email($_POST['username'], $validation_key);

		wp_send_json(array(
			'code' => 200,
			'status' => 'success',
			'message' => 'Your account has been created! You were just sent a verification email. Please validate your account within the next 48 hours to complete your registration. If you don\'t receive an email, please email <a href="mailto:&#099;&#104;&#114;&#105;&#115;&#064;&#103;&#111;&#109;&#097;&#107;&#101;&#116;&#104;&#105;&#110;&#103;&#115;&#046;&#099;&#111;&#109;">&#099;&#104;&#114;&#105;&#115;&#064;&#103;&#111;&#109;&#097;&#107;&#101;&#116;&#104;&#105;&#110;&#103;&#115;&#046;&#099;&#111;&#109;</a>.'
		));

	}
	add_action('wp_ajax_gmt_courses_create_user', 'gmt_courses_create_user');
	add_action('wp_ajax_nopriv_gmt_courses_create_user', 'gmt_courses_create_user');


	/**
	 * Validate a new user account
	 * @return [type] [description]
	 */
	function gmt_courses_validate_new_account () {

		// Bail if not an Ajax request
		if (empty($_SERVER['HTTP_X_REQUESTED_WITH']) || strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) !== 'xmlhttprequest') {
			header('Location: ' . $_SERVER['HTTP_REFERER']);
			return;
		}

		// Bail if user is already logged in
		if (is_user_logged_in()) {
			wp_send_json(array(
				'code' => 401,
				'status' => 'failed',
				'message' => 'You\'re already logged in.'
			));
		}

		// Variables
		$user = get_user_by('email', $_POST['username']);
		$validation = get_user_meta($user->ID, 'user_validation_key', true);
		$signup_url = getenv('SIGNUP_URL');

		// If validation fails
		if (empty($user) || empty($validation) || strcmp($_POST['key'], $validation['key']) !== 0) {
			wp_send_json(array(
				'code' => 401,
				'status' => 'failed',
				'message' => 'This validation link is not valid. If you feel this was in error, please email <a href="mailto:&#099;&#104;&#114;&#105;&#115;&#064;&#103;&#111;&#109;&#097;&#107;&#101;&#116;&#104;&#105;&#110;&#103;&#115;&#046;&#099;&#111;&#109;">&#099;&#104;&#114;&#105;&#115;&#064;&#103;&#111;&#109;&#097;&#107;&#101;&#116;&#104;&#105;&#110;&#103;&#115;&#046;&#099;&#111;&#109;</a>.'
			));
		}

		// If validation key has expired, delete user and ask them to try again
		if (time() > $validation['expires']) {
			wp_delete_user($user->ID);
			wp_send_json(array(
				'code' => 401,
				'status' => 'failed',
				'message' => 'This validation link has expired. Please <a href="' . $signup_url . '">try creating an account again</a>. If you feel this was in error, please email <a href="mailto:&#099;&#104;&#114;&#105;&#115;&#064;&#103;&#111;&#109;&#097;&#107;&#101;&#116;&#104;&#105;&#110;&#103;&#115;&#046;&#099;&#111;&#109;">&#099;&#104;&#114;&#105;&#115;&#064;&#103;&#111;&#109;&#097;&#107;&#101;&#116;&#104;&#105;&#110;&#103;&#115;&#046;&#099;&#111;&#109;</a>.'
			));
		}

		// Remove the validation key
		delete_user_meta($user->ID, 'user_validation_key');

		// Send success data
		wp_send_json(array(
			'code' => 200,
			'status' => 'success',
			'message' => 'Your account was successfully validated. <a href="/">Please login</a> to access your courses.'
		));

	};
	add_action('wp_ajax_gmt_courses_validate_new_account', 'gmt_courses_validate_new_account');
	add_action('wp_ajax_nopriv_gmt_courses_validate_new_account', 'gmt_courses_validate_new_account');


	/**
	 * Update the user's password
	 */
	function gmt_courses_change_password () {

		// Bail if not an Ajax request
		if (empty($_SERVER['HTTP_X_REQUESTED_WITH']) || strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) !== 'xmlhttprequest') {
			header('Location: ' . $_SERVER['HTTP_REFERER']);
			return;
		}

		// Bail if user is already logged in
		if (!is_user_logged_in()) {
			wp_send_json(array(
				'code' => 401,
				'status' => 'failed',
				'message' => 'You need to be logged in to change your password.'
			));
		}

		// Get the current user
		$current_user = wp_get_current_user();

		// Check that current password is supplied
		if (empty($_POST['current_password'])) {
			wp_send_json(array(
				'code' => 401,
				'status' => 'failed',
				'message' => 'Please enter your current password.'
			));
		}

		// Check that new password is provided
		if (empty($_POST['new_password'])) {
			wp_send_json(array(
				'code' => 401,
				'status' => 'failed',
				'message' => 'Please enter enter a new password.'
			));
		}

		// Validate and authenticate current password
		if (!wp_check_password($_POST['current_password'], $current_user->user_pass, $current_user->ID)) {
			wp_send_json(array(
				'code' => 401,
				'status' => 'failed',
				'message' => 'The password you provided is incorrect.'
			));
		}

		// Enforce password requirements
		$pw_length = getenv('MIN_PASSWORD_LENGTH');
		$pw_length = $pw_length ? intval($pw_length) : 8;
		if (strlen($_POST['new_password']) < $pw_length) {
			wp_send_json(array(
				'code' => 401,
				'status' => 'failed',
				'message' => 'Please enter a new password that\'s at least ' . $pw_length . ' characters long.'
			));
		}

		// Update the password
		$update = wp_update_user(array('ID' => $current_user->ID, 'user_pass' => $_POST['new_password']));

		// If update fails
		if (is_wp_error($update)) {
			wp_send_json(array(
				'code' => 401,
				'status' => 'failed',
				'message' => 'Something went wrong. Please try again. If you continue to see this message, please email <a href="mailto:&#099;&#104;&#114;&#105;&#115;&#064;&#103;&#111;&#109;&#097;&#107;&#101;&#116;&#104;&#105;&#110;&#103;&#115;&#046;&#099;&#111;&#109;">&#099;&#104;&#114;&#105;&#115;&#064;&#103;&#111;&#109;&#097;&#107;&#101;&#116;&#104;&#105;&#110;&#103;&#115;&#046;&#099;&#111;&#109;</a>'
			));
		}

		// Success!
		wp_send_json(array(
			'code' => 200,
			'status' => 'success',
			'message' => 'Your password has been updated.'
		));

	}
	add_action('wp_ajax_gmt_courses_change_password', 'gmt_courses_change_password');
	add_action('wp_ajax_nopriv_gmt_courses_change_password', 'gmt_courses_change_password');


	//
	// Helper Methods
	//

	function gmt_courses_get_user_purchases ($email = '') {

		// Variables
		$checkout_url = getenv('CHECKOUT_URL');
		$checkout_username = getenv('CHECKOUT_USERNAME');
		$checkout_pw = getenv('CHECKOUT_PW');

		// Get user purchases
		return json_decode(
			wp_remote_retrieve_body(
				wp_remote_request(
					rtrim($checkout_url, '/') . '/wp-json/gmt-edd/v1/users/' . $email,
					array(
						'method'    => 'GET',
						'headers'   => array(
							'Authorization' => 'Basic ' . base64_encode($checkout_username . ':' . $checkout_pw),
						),
					)
				)
			)
		);

	}


	function gmt_courses_get_user_courses ($email = '') {

		// Variables
		$course_data = getenv('COURSE_DATA');
		$purchases = gmt_courses_get_user_purchases($email);

		// Bail if the user has no purchases
		if (empty($purchases)) return;

		// Get course data and remove courses the user doesn't have access to
		$courses = json_decode(file_get_contents(realpath(ABSPATH . DIRECTORY_SEPARATOR . '..') . '/' . trim($course_data, '/'), true));
		foreach ($courses->courses as $key => $course) {
			if (in_array($course->id, $purchases)) continue;
			unset($courses->courses[$key]);
		}

		return $courses;

	}

	/**
	 * Get the site domain and remove the www.
	 * @return String The site domain
	 */
	function gmt_courses_get_site_domain() {
		$sitename = strtolower( $_SERVER['SERVER_NAME'] );
		if ( substr( $sitename, 0, 4 ) == 'www.' ) {
			$sitename = substr( $sitename, 4 );
		}
		return $sitename;
	}


	/**
	 * Send validation email to a new user
	 * @param  String $email The new user's email
	 * @param  String $key   The new user's validation key
	 */
	function gmt_courses_send_validation_email ($email, $key) {

		// Variables
		$validate_url = getenv('VALIDATE_URL');
		$site_name = get_bloginfo('name');
		$domain = gmt_courses_get_site_domain();
		$headers = 'From: ' . $site_name . ' <donotreply@' . $domain . '>' . "\r\n";
		$subject = 'Validate your new account at ' . $site_name;
		$message = 'Please click the link below to validate your new account at ' . $site_name . '. If you did not try to create an account at ' . $site_name . ', ignore this email and nothing will happen.' . "\r\n" . $validate_url . '?email=' . $email . '&key=' . $key;

		// Send email
		@wp_mail(sanitize_email($email), $subject, $message, $headers);

	}


	// Disable default new user admin notifications
	if ( !function_exists( 'wp_new_user_notification' ) ) {
		function wp_new_user_notification() {}
	}



	/**
	 * Redirect users away from the front end
	 */
	function gmt_courses_redirect_from_front_end () {
		$url = getenv('FRONTEND_URL');
		if (is_admin() || empty($url)) return;
		wp_redirect($url);
		exit;
	}
	add_action('init', 'gmt_courses_redirect_from_front_end');