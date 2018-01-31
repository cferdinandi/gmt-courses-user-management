<?php

/**
 * Plugin Name: GMT Courses User Management
 * Plugin URI: https://github.com/cferdinandi/gmt-courses-user-management/
 * GitHub Plugin URI: https://github.com/cferdinandi/gmt-courses-user-management/
 * Description: User processes for GMT Courses.
 * Version: 0.0.1
 * Author: Chris Ferdinandi
 * Author URI: http://gomakethings.com
 * License: GPLv3
 */


	// @notes
	// * Use wp_send_json() - https://codex.wordpress.org/Function_Reference/wp_send_json
	// * Use the WP Ajax functionality for this?
	// 		- https://codex.wordpress.org/AJAX_in_Plugins
	// 		- https://www.smashingmagazine.com/2011/10/how-to-use-ajax-in-wordpress/
	// 		- endpoint: /wp-admin/admin-ajax.php

	function test_thing () {

		if(!empty($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) == 'xmlhttprequest') {
			$courses = json_decode(file_get_contents(ABSPATH . '/testing/course-data.json', true));
			wp_send_json($courses);
		}
		else {
			header('Location: ' . $_SERVER['HTTP_REFERER']);
		}

		// echo wp_send_json(array('chicken', 'beef'));

	}
	add_action('wp_ajax_test_thing', 'test_thing');
	add_action('wp_ajax_nopriv_test_thing', 'test_thing');

	// atomic.ajax({
	// 	type: 'POST',
	// 	url: 'http://localhost:8888/go-make-things-courses-backend/wp-admin/admin-ajax.php',
	// 	headers: {
	// 		'X-Requested-With': 'XMLHttpRequest'
	// },
	// 	data: {
	// 		action: 'test_thing',
	// 		fake: 'thing 1'
	// 	}
	// }).success(function (data, xhr) {
	// 	console.log(data);
	// });


	//
	// AJAX Methods
	//

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

		// Get user purchases
		$courses = gmt_courses_get_user_courses($_POST['username']);

		// Send data back
		wp_send_json(array(
			'code' => 200,
			'status' => 'success',
			'data' => array(
				'email' => $_POST['username'],
				'data' => $courses
			)
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

		// Get user purchases
		$courses = gmt_courses_get_user_courses($_POST['username']);

		// If user hasn't made any purchases
		if (empty($purchases) || !filter_var($data['email'], FILTER_VALIDATE_EMAIL) || !validate_username($_POST['username'])) {
			wp_send_json(array(
				'code' => 401,
				'status' => 'failed',
				'message' => 'Please use the same email address that you use to purchase your courses.'
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
		$pw_length = $pw_length ? $pw_length : 8;
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
		$validation_key =  wp_generate_password(48);
		set_transient('validate_user_' . $_POST['username'], $validation_key, 60 * 60 * 48);

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

		// Variables
		$user = get_user_by('email', $_POST['username']);
		$validation = get_transient('validate_user_' . $_POST['username']);

		// If validation fails
		if (empty($user) || empty($validation) || strcmp($_POST['key'], $validation) !== 0) {
			wp_send_json(array(
				'code' => 401,
				'status' => 'failed',
				'message' => 'This validation link is not valid. If you feel this was in error, please email <a href="mailto:&#099;&#104;&#114;&#105;&#115;&#064;&#103;&#111;&#109;&#097;&#107;&#101;&#116;&#104;&#105;&#110;&#103;&#115;&#046;&#099;&#111;&#109;">&#099;&#104;&#114;&#105;&#115;&#064;&#103;&#111;&#109;&#097;&#107;&#101;&#116;&#104;&#105;&#110;&#103;&#115;&#046;&#099;&#111;&#109;</a>.'
			));
		}

		// Send data back
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
		$pw_length = $pw_length ? $pw_length : 8;
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
		return wp_remote_request(
			rtrim($checkout_url, '/') . '/wp-json/gmt-edd/v1/users/' . $email,
			array(
				'method'    => 'GET',
				'headers'   => array(
					'Authorization' => 'Basic ' . base64_encode($checkout_username . ':' . $checkout_pw),
				),
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
		$courses = json_decode(file_get_contents(realpath(ABSPATH . DIRECTORY_SEPARATOR . '..') . $course_data, true));
		foreach ($courses->courses as $key => $course) {
			if (in_array($course->id, $purchases)) continue;
			unset($courses->courses[$key]);
		}

		return $courses;

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
		$domain = wpwebapp_get_site_domain();
		$headers = 'From: ' . $site_name . ' <donotreply@' . $domain . '>' . "\r\n";
		$subject = 'Validate your new account at ' . $site_name;
		$message = 'Please click the link below to validate your new account at ' . $site_name . '. If you did not try to create an account at ' . $site_name . ', ignore this email and nothing will happen.' . "\n\n" . $validate_url . '?email=' . $email . '&key=' . $key;

		// Send email
		$email = @wp_mail(sanitize_email($email), $subject, $message, $headers);

	}


	// Disable default new user admin notifications
	if ( !function_exists( 'wp_new_user_notification' ) ) {
		function wp_new_user_notification() {}
	}