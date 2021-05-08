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
					)
				)
			)
		);

	}


	/**
	 * Get products purchased by the user
	 * @param  string $email The user's email address
	 * @return array         The products purchased by the user
	 */
	function gmt_courses_get_user_products ($email = '') {

		// Variables
		$product_data_file = getenv('COURSE_DATA');
		$user_data = gmt_courses_get_user_purchases($email);
		$purchases = $user_data->purchases;
		if (gettype($purchases) === 'object') {
			$purchases = get_object_vars($purchases);
		}

		// Bail if the user has no purchases
		if (empty($purchases)) return;

		// Get product data
		$product_data = json_decode(file_get_contents(realpath(ABSPATH . DIRECTORY_SEPARATOR . '..') . '/' . trim($product_data_file, '/'), true));

		// Setup products object
		$products = array(
			'invoices' => $user_data->invoices,
			'resources' => $product_data->resources,
			'academy' => array(),
			'guides' => array(),
			'products' => array(),
		);

		// Get purchased Academy memberships
		foreach($product_data->academy as $key => $session) {
			if (in_array($session->id, $purchases) || (!empty($session->monthly) && in_array($session->monthly, $purchases))) {
				$products['academy'][] = array(
					'id' => $session->id,
					'title' => $session->title,
					'url' => $session->url,
					'slack' => $session->slack,
					'completed' => $session->completed,
					'lessons' => $session->lessons,
				);
			}
		}

		// Get purchased pocket guides
		foreach($product_data->guides as $key => $guide) {
			if (in_array($guide->id, $purchases)) {
				$has_book = array_intersect(array($guide->id . '_1', $guide->id . '_3'), $purchases);
				$has_video = array_intersect(array($guide->id . '_2', $guide->id . '_3'), $purchases);
				$products['guides'][] = array(
					'id' => $guide->id,
					'title' => $guide->title,
					'url' => $guide->url,
					'sourceCode' => $guide->sourceCode,
					'lessons' => ($has_video ? $guide->lessons : null),
					'assets' => ($has_book ? $guide->assets : null),
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
					'assets' => $product->assets,
				);
			}
		}

		return $products;

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