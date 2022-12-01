<?php

	// Security
	if (!defined('ABSPATH')) exit;


	//
	// API Methods
	//

	/**
	 * Check if request is not Ajax
	 * @return Boolean If true, is not Ajax
	 */
	function gmt_courses_is_not_ajax () {
		return empty($_SERVER['HTTP_X_REQUESTED_WITH']) || strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) !== 'xmlhttprequest';
	}

	/**
	 * Check if reset key has expired
	 * @param  Array   $reset_key The reset key array
	 * @return Boolean            If true, reset key has expired
	 */
	function gmt_courses_has_reset_key_expired ($reset_key) {
		return !empty($reset_key['expires']) && time() > $reset_key['expires'];
	}

	/**
	 * Get the minimum password length
	 * @return Integer The minimum password length
	 */
	function gmt_courses_get_pw_length () {
		$pw_length = getenv('MIN_PASSWORD_LENGTH');
		$pw_length = $pw_length ? intval($pw_length) : 8;
		return $pw_length;
	}

	/**
	 * Check if the password is too short
	 * @param  String  $pw        The password
	 * @param  Integer $pw_length The minimum length
	 * @return Boolean            If true, password is too short
	 */
	function gmt_courses_is_pw_too_short ($pw, $pw_length) {
		return strlen($pw) < $pw_length;
	}


	//
	// Product Methods
	//

	/**
	 * Get a list of purchases made with the user's email address
	 * @param  string $email The user's email address
	 * @return array         The user's purchases
	 */
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
						'sslverify' => false,
					)
				)
			)
		);

	}


	/**
	 * Get subscription data for a user
	 * @param  string $email The user's email address
	 * @return array         The user's subscription data
	 */
	function gmt_courses_get_user_subscription_data ($email = '') {

		// Variables
		$checkout_url = getenv('CHECKOUT_URL');
		$checkout_username = getenv('CHECKOUT_USERNAME');
		$checkout_pw = getenv('CHECKOUT_PW');

		// Get user purchases
		return json_decode(
			wp_remote_retrieve_body(
				wp_remote_request(
					rtrim($checkout_url, '/') . '/wp-json/gmt-edd/v1/subscriptions/' . $email,
					array(
						'method'    => 'GET',
						'headers'   => array(
							'Authorization' => 'Basic ' . base64_encode($checkout_username . ':' . $checkout_pw),
						),
						'sslverify' => false,
					)
				)
			)
		);

	}

	/**
	 * Get the update link for a failed subscription
	 * @param  Object $subscription The subscription data
	 * @return String               The subscription link
	 */
	function gmt_courses_get_failed_subscription_link ($subscription) {

		// Only run for failing subscriptions
		if ($subscription->status !== 'failing') return null;

		// For PayPal
		if (strpos($subscription->gateway, 'paypal') > -1) {
			return 'Please update your payment settings in PayPal';
		}

		// For Stripe
		if (strpos($subscription->gateway, 'stripe') > -1) {
			$notes = array_reverse(explode("\n\n", $subscription->notes));
			foreach ($notes as $note) {
				if (strpos($note, 'Failing invoice URL:') < 0) continue;
				$url = explode('Failing invoice URL: ', $note);
				if (!empty($url[1])) return $url[1];
			}
		}

		return null;

	}

	/**
	 * Get the formatted gateway name
	 * @param  String $gateway The gateway
	 * @return String          The gateway name
	 */
	function gmt_courses_get_subscription_gateway ($gateway) {
		if (strpos($gateway, 'paypal') > -1) return 'PayPal';
		if (strpos($gateway, 'stripe') > -1) return 'credit card';
		return ucwords($gateway);
	}

	/**
	 * Get a list of subscriptions for a user
	 * @param  string $email The user's email address
	 * @return array         The user's subscriptions
	 */
	function gmt_courses_get_user_subscriptions ($email = '') {

		// Get subscription data
		$subscription_data = gmt_courses_get_user_subscription_data($email);
		if (is_null($subscription_data)) return;

		// Create subscription list
		$subscriptions = array();
		foreach ($subscription_data as $index => $subscription) {
			$subscriptions[] = array(
				'status' => $subscription->status,
				'amount' => $subscription->recurring_amount,
				'product' => $subscription->product,
				'gateway' => gmt_courses_get_subscription_gateway($subscription->gateway),
				'billTimes' => $subscription->bill_times,
				'timesBilled' => strval($subscription->times_billed),
				'failURL' => gmt_courses_get_failed_subscription_link($subscription),
			);
		}

		return $subscriptions;

	}


	/**
	 * Get summary of products purchased by the user
	 * @param  string $email The user's email address
	 * @return array         The summary of products purchased by the user
	 */
	function gmt_courses_get_user_invoices ($email = '') {
		$user_data = gmt_courses_get_user_purchases($email);
		if (empty($user_data) || !property_exists($user_data, 'invoices')) return;
		return $user_data->invoices;
	}


	/**
	 * Get summary of products purchased by the user
	 * @todo Remove invoices from this
	 * @param  string $email The user's email address
	 * @return array         The summary of products purchased by the user
	 */
	function gmt_courses_get_user_product_summary ($email = '') {

		// Get user data
		$user_data = gmt_courses_get_user_purchases($email);
		if (empty($user_data) || !property_exists($user_data, 'purchases')) return;

		// Get purchases for user
		$purchases = $user_data->purchases;
		if (gettype($purchases) === 'object') {
			$purchases = get_object_vars($purchases);
		}

		// Bail if the user has no purchases
		if (empty($purchases)) return;

		// Get product data
		$product_data = json_decode(file_get_contents(realpath(ABSPATH . DIRECTORY_SEPARATOR . '..') . '/index.json'), false);

		// Setup products object
		$products = array(
			'resources' => $product_data->resources,
			'academy' => array(),
			'guides' => array(),
			'products' => array(),
			'slack' => false,
		);

		// Get purchased Academy memberships
		foreach($product_data->academy as $key => $session) {
			if (in_array($session->id, $purchases) || (!empty($session->monthly) && in_array($session->monthly, $purchases))) {
				$products['academy'][] = array(
					'id' => $session->id,
					'title' => $session->title,
					'url' => $session->url,
					'slack' => $session->slack, // Do not delete - used for Slack access
					'completed' => $session->completed,
				);
			}
		}

		// Get purchased pocket guides
		foreach($product_data->guides as $key => $guide) {
			if (!empty(array_intersect(array($guide->id . '_1', $guide->id . '_2', $guide->id . '_3'), $purchases))) {
				$products['guides'][] = array(
					'id' => $guide->id,
					'title' => $guide->title,
					'url' => $guide->url,
				);
			}
		}

		// Get other purchased products
		foreach($product_data->products as $key => $product) {
			if (in_array($product->id, $purchases)) {
				$products['products'][] = array(
					'id' => $product->id,
					'title' => $product->title,
					'url' => $product->url,
				);
			}
		}

		// Check for Slack access
		if (!empty($products['academy'])) {
			$products['slack'] = true;
		} else {
			foreach($product_data->slack as $product_id) {
				if (in_array($product_id, $purchases)) {
					$products['slack'] = true;
					break;
				}
			}
		}

		// Remove Slack from resources if user doesn't have access
		if (empty($products['slack'])) {
			foreach ($products['resources'] as $index => $resource) {
				if (strpos($resources->url, 'slack') > -1) {
					unset($products['resources'][$index]);
				}
			}
		}

		return $products;

	}


	/**
	 * Get details for product purchased by the user
	 * @param  string $email The user's email address
	 * @return array         The products purchased by the user
	 */
	function gmt_courses_get_user_product_details ($email = '', $type = '', $api_dir = '') {

		// Ensure correct data provided
		if (empty($type) || empty($api_dir)) return;

		// Variables
		$user_data = gmt_courses_get_user_purchases($email);
		$purchases = $user_data->purchases;
		if (gettype($purchases) === 'object') {
			$purchases = get_object_vars($purchases);
		}

		// Bail if the user has no purchases
		if (empty($purchases)) return;

		// Get product data
		$product_data = json_decode(file_get_contents(realpath(ABSPATH . DIRECTORY_SEPARATOR . '..') . '/' . trim($api_dir, '/') . '/index.json'), false);

		// Make sure user has access to purchase
		$has_product = $type === 'guides' ? array_intersect(array($product_data->id . '_1', $product_data->id . '_2', $product_data->id . '_3'), $purchases) : in_array($product_data->id, $purchases);
		if (empty($has_product) && (empty($product_data->monthly) || !in_array($product_data->monthly, $purchases))) return;

		// If not pocket guides
		if ($type !== 'guides') {
			unset($product_data->monthly);
			unset($product_data->slack);
			return $product_data;
		}

		// If a Pocket Guide
		if ($type === 'guides') {
			$has_book = array_intersect(array($product_data->id . '_1', $product_data->id . '_3'), $purchases);
			$has_video = array_intersect(array($product_data->id . '_2', $product_data->id . '_3'), $purchases);
			return array(
				'id' => $product_data->id,
				'title' => $product_data->title,
				'url' => $product_data->url,
				'sourceCode' => $product_data->sourceCode,
				'lessons' => ($has_video ? $product_data->lessons : null),
				'assets' => ($has_book ? $product_data->assets : null),
				'has_book' => $has_book,
				'has_video' => $has_video,
			);
		}

	}


	/**
	 * Get special Slack channels for Academy
	 * @param  Object $products The user's product data
	 * @return Array            The Slack channels
	 */
	function gmt_courses_get_slack_channels ($products) {

		// If user doesn't have academy, no special channels to add
		if (empty($products) || empty($products['academy'])) return array();

		// Get Academy channels
		$channels = array();
		foreach($products['academy'] as $session) {
			if ($session['completed']) continue;
			$channels[] = $session['slack'];
		}

		return empty($channels) ? $channels : array('channels' => implode(',', $channels));

	}



	//
	// Utilities
	//

	/**
	 * Get an encoded email link
	 * @return string The email link
	 */
	function gmt_courses_get_email () {
		return '<a href="mailto:&#099;&#104;&#114;&#105;&#115;&#064;&#103;&#111;&#109;&#097;&#107;&#101;&#116;&#104;&#105;&#110;&#103;&#115;&#046;&#099;&#111;&#109;">&#099;&#104;&#114;&#105;&#115;&#064;&#103;&#111;&#109;&#097;&#107;&#101;&#116;&#104;&#105;&#110;&#103;&#115;&#046;&#099;&#111;&#109;</a>';
	};


	/**
	 * Get the site domain and remove the www.
	 * @return string The site domain
	 */
	function gmt_courses_get_site_domain() {
		$sitename = strtolower( $_SERVER['SERVER_NAME'] );
		if ( substr( $sitename, 0, 4 ) == 'www.' ) {
			$sitename = substr( $sitename, 4 );
		}
		return $sitename;
	}