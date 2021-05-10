<?php

	// Security
	if (!defined('ABSPATH')) exit;

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
	add_filter( 'send_password_change_email', '__return_false' );



	/**
	 * Hide default rest API endpoints
	 */
	remove_action('rest_api_init', 'create_initial_rest_routes', 99);



	/**
	 * Prevent RSS feed caching
	 * @param  Object $feed The RSS feed
	 */
	function gmt_courses_do_not_cache_feeds($feed) {
		$feed->enable_cache(false);
	}
	add_action('wp_feed_options', 'gmt_courses_do_not_cache_feeds');



	/**
	 * Redirect users away from the front end
	 */
	function gmt_courses_api_redirect_from_front_end () {
		$url = getenv('FRONTEND_URL');
		if (is_admin() || empty($url) || $GLOBALS['pagenow'] === 'wp-login.php' || in_array('wp-json', explode('/', $_SERVER['REQUEST_URI'])) || !empty($_GET['feed'])) return;
		wp_redirect($url);
		exit;
	}
	add_action('init', 'gmt_courses_api_redirect_from_front_end');