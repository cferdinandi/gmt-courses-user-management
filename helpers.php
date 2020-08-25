<?php

	//
	// Checks
	//

	/**
	 * Check if the request is from an allowed domain
	 * @param  array   $request The request object
	 * @return boolean          If true, the request is allowed
	 */
	function gmt_courses_api_is_allowed_domain ($request) {
		$origins = getenv('API_ORIGINS');
		$origin = $request->get_header('host');
		if (empty($origins) || in_array($origin, explode(',', $origins))) return true;
		return false;
	}

	/**
	 * Check if a reset key exists
	 * @param array  $user      The user object
	 * @param string $key       The user's reset key
	 * @param string $reset_key The reset key in the DB
	 * @return boolean          If true, reset key exists
	 */
	function gmt_courses_api_is_reset_key ($user, $key, $reset_key) {
		if (empty($user) || empty($reset_key) || strcmp($key, $reset_key) !== 0) return false;
		return true;
	}

	/**
	 * Check if reset key has expired
	 * @param  integer $expires Expiration timestamp
	 * @return boolean          If true, key has expired
	 */
	function gmt_courses_api_has_key_expired ($expires) {
		if (time() > $expires) return true;
		return false;
	}



	//
	// Product Methods
	//

	/**
	 * Get a list of purchases made with the user's email address
	 * @param  string $email The user's email address
	 * @return array         The user's purchases
	 */
	function gmt_courses_api_get_user_purchases ($email = '') {

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
	function gmt_courses_api_get_user_products ($email = '') {

		// Variables
		$product_data_file = getenv('COURSE_DATA');
		$user_data = gmt_courses_api_get_user_purchases($email);
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
			if (in_array($session->id, $purchases)) {
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

	/**
	 * Get a specific product by it's ID
	 * @param  array   $products The products array
	 * @param  string $id        The product ID
	 * @return array             The product
	 */
	function gmt_courses_api_get_product_by_id ($products, $id) {
		$id = strval($id);
		foreach ($products as $key => $product) {
			if (strval($product->id) === $id) return $product;
		}
		return false;
	}

	/**
	 * Get product if purchased by the user
	 * @param  string $email The user's email address
	 * @param  string $id    The product ID
	 * @return array         The products purchased by the user
	 */
	function gmt_courses_api_get_user_product ($email = '', $id = '', $type = '') {

		// Variables
		$product_data_file = getenv('COURSE_DATA');
		$user_data = gmt_courses_api_get_user_purchases($email);
		$purchases = $user_data->purchases;
		if (gettype($purchases) === 'object') {
			$purchases = get_object_vars($purchases);
		}
		$has_book = false;
		$has_video = false;

		// Bail if the user has not purchased the product
		if (empty($purchases)) return ;
		if ($type === 'academy' || $type === 'products') {
			if (empty(in_array(intval($id), $purchases))) return;
		} else {
			$has_book = array_intersect(array($id . '_1', $id . '_3'), $purchases);
			$has_video = array_intersect(array($id . '_2', $id . '_3'), $purchases);
			if (empty($has_book) && empty($has_video)) return;
		}

		// Get product data
		$product_data = json_decode(file_get_contents(realpath(ABSPATH . DIRECTORY_SEPARATOR . '..') . '/' . trim($product_data_file, '/'), true));

		// Get product by ID
		$product = gmt_courses_api_get_product_by_id($product_data->$type, $id);
		if (empty($product)) return;

		// If Academy, return product as-is
		if ($type === 'academy' || $type === 'products') return $product;

		// If the user doesn't have access to the ebook files, remove them
		if (empty($has_book)) {
			$product->assets = null;
		}

		// If the user doesn't have access to the video lessons, remove them
		if (empty($has_video)) {
			$product->lessons = null;
		}

		return $product;

	}


	//
	// Utilities
	//

	/**
	 * Get an encoded email link
	 * @return string The email link
	 */
	function gmt_courses_api_get_email () {
		return '<a href="mailto:&#099;&#104;&#114;&#105;&#115;&#064;&#103;&#111;&#109;&#097;&#107;&#101;&#116;&#104;&#105;&#110;&#103;&#115;&#046;&#099;&#111;&#109;">&#099;&#104;&#114;&#105;&#115;&#064;&#103;&#111;&#109;&#097;&#107;&#101;&#116;&#104;&#105;&#110;&#103;&#115;&#046;&#099;&#111;&#109;</a>';
	};

	/**
	 * Get the site domain and remove the www.
	 * @return string The site domain
	 */
	function gmt_courses_api_get_site_domain () {
		$sitename = strtolower( $_SERVER['SERVER_NAME'] );
		if ( substr( $sitename, 0, 4 ) == 'www.' ) {
			$sitename = substr( $sitename, 4 );
		}
		return $sitename;
	}