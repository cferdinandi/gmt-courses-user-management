<?php

	// Security
	if (!defined('ABSPATH')) exit;


	/**
	 * Send validation email to a new user
	 * @param  string $email The new user's email
	 * @param  string $key   The new user's validation key
	 */
	function gmt_courses_send_validation_email ($email, $key) {

		// Variables
		$validate_url = getenv('VALIDATE_URL');
		$site_name = get_bloginfo('name');
		$domain = gmt_courses_get_site_domain();
		$headers = 'From: ' . $site_name . ' <donotreply@' . $domain . '>' . "\r\n";
		$subject = 'Validate your new account at ' . $site_name;
		$message = 'Please click the link below to validate your new account at ' . $site_name . '. If you did not try to create an account at ' . $site_name . ', ignore this email and nothing will happen.' . "\r\n\r\n" . $validate_url . '?email=' . urlencode($email) . '&key=' . urlencode($key);

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