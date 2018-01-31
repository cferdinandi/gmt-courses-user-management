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

	// @todo API endpoint to create a new user
	// 1. Validate that they have purchases via the new WP Rest API endpoint
	// 2. Create account with password and add user meta key
	// 3. Email them a link (valid for 48 hours) to click to authenticate account
	function test_thing () {

		// if(!empty($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) == 'xmlhttprequest') {
		// 	$result = json_encode(array('chicken', 'beef'));
		// 	echo $result;
		// }
		// else {
		// 	header('Location: ' . $_SERVER['HTTP_REFERER']);
		// }

		echo wp_send_json(array('chicken', 'beef'));

	}
	add_action('wp_ajax_test_thing', 'test_thing');
	add_action('wp_ajax_nopriv_test_thing', 'test_thing');

	// atomic.ajax({
	// 	type: 'POST',
	// 	url: 'http://localhost:8888/go-make-things-courses-backend/wp-admin/admin-ajax.php',
	// 	data: {
	// 		action: 'test_thing',
	// 		fake: 'thing 1'
	// 	}
	// }).success(function (data, xhr) {
	// 	console.log(data);
	// });


	// @todo API endpoint to sign user in
	// 1. Validate username and password
	// 2. Log them in
	// 3. Make WP Rest API call to get purchases
	// 4. Respond to API with purchases