<?php

/**
 * Plugin Name: GMT Courses User Management
 * Plugin URI: https://github.com/cferdinandi/gmt-courses-user-management/
 * GitHub Plugin URI: https://github.com/cferdinandi/gmt-courses-user-management/
 * Description: User processes for GMT Courses.
 * Version: 5.0.3
 * Author: Chris Ferdinandi
 * Author URI: http://gomakethings.com
 * License: GPLv3
 *
 * Notes and references:
 * - https://codex.wordpress.org/Function_Reference/wp_send_json
 * - https://codex.wordpress.org/AJAX_in_Plugins
 * - https://www.smashingmagazine.com/2011/10/how-to-use-ajax-in-wordpress/
 *
 * New API:
 * - https://developer.wordpress.org/rest-api/
 * - https://www.sitepoint.com/php-sessions/
 * - https://www.tutorialspoint.com/php/php_sessions.htm
 */

	// Security
	if (!defined('ABSPATH')) exit;

	// WP Ajax
	require_once('helpers.php');
    require_once('slack.php');
	require_once('emails.php');
	require_once('ajax.php');
	require_once('access.php');
    require_once('account.php');