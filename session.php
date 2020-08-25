<?php

	/**
	 * Create session details
	 * @return array The session details
	 */
	function gmt_courses_api_get_session_options () {
		return array(
			'cookie_lifetime' => 60 * 60 * 24 * 14, // 2 weeks
			'gc_maxlifetime' => 60 * 60 * 24 * 14, // 2 weeks
		);
	}

	/**
	 * Start a new user session
	 * @return string The session token
	 */
	function gmt_courses_api_start_session ($email, $token) {
		session_start(gmt_courses_api_get_session_options());
		if (empty($token)) {
			$token = wp_generate_password(48, false);
		}
		$_SESSION['auth_email'] = $email;
		$_SESSION['auth_token'] = $token;
		$_SESSION['auth_token_last_access'] = time();
		return array(
			'token' => $token,
			'username' => $email
		);
	}

	/**
	 * End a user session
	 */
	function gmt_courses_api_end_session () {
		session_start(gmt_courses_api_get_session_options());
		unset($_SESSION['auth_email']);
		unset($_SESSION['auth_token']);
		unset($_SESSION['auth_token_last_access']);
	}

	/**
	 * Extend a user session
	 * @return boolean If true, session successfully extended
	 */
	function gmt_courses_api_extend_session () {
		session_start(gmt_courses_api_get_session_options());
		$email = $_SESSION['auth_email'];
		$token = $_SESSION['auth_token'];
		gmt_courses_api_end_session();
		gmt_courses_api_start_session($email, $token);
		return true;
	}

	/**
	 * Check if user session is expired (default duration is 2 weeks)
	 * @return boolean If true, session is expired
	 */
	function gmt_courses_api_is_token_expired () {

		// Variables
		$expires = getenv('SESSION_DURATION');
		if (empty($expires)) {
			$expires = 60 * 60 * 24 * 14;
		}

		// Check expiration
		session_start(gmt_courses_api_get_session_options());
		if (empty($_SESSION['auth_token_last_access']) || ($_SESSION['auth_token_last_access'] + $expires) < time()) return true;
		return false;

	}

	/**
	 * Check if a session token is valid
	 * @param  string  $token The session token
	 * @return boolean        If true, the token is valid
	 */
	function gmt_courses_api_is_token_valid ($token) {
		session_start(gmt_courses_api_get_session_options());
		if (!empty($token) && !empty($_SESSION['auth_token']) && strcmp($token, $_SESSION['auth_token']) === 0 && !gmt_courses_api_is_token_expired()) return true;
		return false;
	}

	/**
	 * Get the user email after authenticating their token
	 * @deprecated never used, but may be in the future
	 * @param  string $token The session token
	 * @return string        The user's email
	 */
	function gmt_courses_api_get_user_authenticated ($token) {
		session_start(gmt_courses_api_get_session_options());
		if (empty(gmt_courses_api_is_token_valid($token)) || empty($_SESSION['auth_email'])) return false;
		return $_SESSION['auth_email'];
	}

	/**
	 * Check if there's an active user session
	 * @param  string  $token The user session token
	 * @return boolean        If true, there's a current session
	 */
	function gmt_courses_api_is_authenticated ($token) {
		session_start(gmt_courses_api_get_session_options());
		if (!empty($_SESSION['auth_email']) && !empty(gmt_courses_api_is_token_valid($token)) && !gmt_courses_api_is_token_expired()) {
			gmt_courses_api_extend_session();
			return true;
		}
		return false;
	}

	/**
	 * Get the user email
	 * @return string The user email
	 */
	function gmt_courses_api_get_user () {
		session_start(gmt_courses_api_get_session_options());
		if (empty($_SESSION['auth_email']) || gmt_courses_api_is_token_expired()) return false;
		return $_SESSION['auth_email'];
	}