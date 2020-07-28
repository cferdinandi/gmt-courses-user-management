<?php

	/**
	 * Disable Notifications
	 * @todo  make these configurable with environment variables
	 */

	// Disable default new user admin notifications
	if ( !function_exists( 'wp_new_user_notification' ) ) {
		function wp_new_user_notification() {}
	}

	// Disable user password reset notification to admin
	if ( ! function_exists( 'wp_password_change_notification' ) ) {
		function wp_password_change_notification( $user ) {
			return;
		}
	}

	// Disable password change notification to the user
	add_filter( 'send_email_change_email', '__return_false' );



	/**
	 * Redirect users away from the front end
	 */
	function gmt_courses_api_redirect_from_front_end () {
		$url = getenv('FRONTEND_URL');
		if (is_admin() || empty($url) || $GLOBALS['pagenow'] === 'wp-login.php') return;
		wp_redirect($url);
		exit;
	}
	add_action('init', 'gmt_courses_api_redirect_from_front_end');