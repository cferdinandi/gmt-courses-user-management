<?php

	/**
	 * Start a new user session
	 * @return string The session token
	 */
	function gmt_courses_api_start_session ($email) {
		session_start();
		$token = wp_generate_password(48, false);
		$_SESSION['auth_email'] = $email;
		$_SESSION['auth_token'] = $token;
		$_SESSION['auth_token_last_access'] = time();
		return array(
			'token' => $token,
			'username' => $email
		);
	}

	function gmt_courses_api_end_session () {
		session_start();
		unset($_SESSION['auth_email']);
		unset($_SESSION['auth_token']);
		unset($_SESSION['auth_token_last_access']);
	}

	function gmt_courses_api_is_token_expired () {

		// Variables
		$expires = getenv('SESSION_DURATION');
		if (empty($expires)) {
			$expires = 60 * 60 * 24 * 14;
		}

		// Check expiration
		session_start();
		if (empty($_SESSION['auth_token_last_access']) || ($_SESSION['auth_token_last_access'] + $expires) < time()) return true;
		return false;

	}

	function gmt_courses_api_is_token_valid ($token) {
		session_start();
		if (!empty($token) && !empty($_SESSION['auth_token']) && strcmp($token, $_SESSION['auth_token']) === 0 && !gmt_courses_api_is_token_expired()) return true;
		return false;
	}

	function gmt_courses_api_get_user_authenticated ($token) {
		session_start();
		if (empty(gmt_courses_api_is_token_valid($token)) || empty($_SESSION['auth_email'])) return false;
		return $_SESSION['auth_email'];
	}

	function gmt_courses_api_get_user () {
		session_start();
		if (empty($_SESSION['auth_email']) || gmt_courses_api_is_token_expired()) return false;
		return $_SESSION['auth_email'];
	}

	function gmt_courses_api_is_logged_in () {
		session_start();
		if (empty($_SESSION['auth_email'])) return false;
		if (gmt_courses_api_is_token_expired()) return false;
		return true;
	}