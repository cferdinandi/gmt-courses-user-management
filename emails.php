<?php

	// Security
	if (!defined('ABSPATH')) exit;


	/**
	 * Send account created email to a new user
	 * @param  string $email The new user's email
	 */
	function gmt_courses_send_account_created_email ($email) {

		// Variables
		$site_name = get_bloginfo('name');
		$domain = gmt_courses_get_site_domain();
		$headers = 'From: ' . $site_name . ' <' . get_option('admin_email') . '>' . "\r\n";
		$subject = 'Your account was created for ' . $site_name;
		$message = 'An account was created for ' . $email . ' at ' . $site_name . '. If you did not initiate this action, please email Chris at ' . get_option('admin_email') . '.';

		// Send email
		@wp_mail(sanitize_email($email), $subject, $message, $headers);

	}


	/**
	 * Send password reset email to user
	 * @param  string $email The user's email
	 * @param  string $key   The reset validation key
	 */
	function gmt_courses_send_pw_reset_email ($email, $key) {

		// Variables
		$reset_pw_url = getenv('RESET_PW_URL');
		$site_name = get_bloginfo('name');
		$domain = gmt_courses_get_site_domain();
		$headers = 'From: ' . $site_name . ' <donotreply@' . $domain . '>' . "\r\n";
		$subject = 'Reset your password for ' . $site_name;
		$message = 'Please click the link below to reset your password for ' . $site_name . '. If you did not try to reset your password for ' . $site_name . ', ignore this email and nothing will happen.' . "\r\n\r\n" . $reset_pw_url . '?email=' . $email . '&key=' . $key;

		// Send email
		@wp_mail(sanitize_email($email), $subject, $message, $headers);

	}