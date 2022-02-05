<?php
/**
 * This class handles API call to slack.com.
 *
 * @package    Gravityforms Slack Invite Automation
 * @author     Jignesh Nakrani <jignesh.nakrani>
 */

	class Slack_Invite {

		protected $api_url = 'https://slack.com/api/';

		function __construct( $auth_token, $team_domain ) {

			$this->auth_token = $auth_token;
			$this->team_domain = $team_domain;
			$this->api_url = 'https://' . $team_domain . '.slack.com/api/';
		}

		/**
		 * Make API request.
		 *
		 * @access public
		 * @param string $path
		 * @param array $options
		 * @param bool $return_status (default: false)
		 * @param string $method (default: 'GET')
		 * @return void
		 */
		function make_request( $path, $options = array(), $method = 'GET' ) {

			/* Build base request options string. */
			$request_options = '?token='. $this->auth_token;

			/* Add options if this is a GET request. */
			$request_options .= ( $method == 'GET' && ! empty( $options ) ) ? '&'. http_build_query( $options ) : null;

			/* Build request URL. */
			$request_url = $this->api_url . $path . $request_options;

			/* Execute request based on method. */

			switch ( $method ) {

				case 'POST':
					$args = array(
						'body' => $options
					);
					$response = wp_remote_post( $request_url, $args );
					break;

				case 'GET':
					$response = wp_remote_get( $request_url );
					break;

			}

			/* If WP_Error, die. Otherwise, return decoded JSON. */
			if ( is_wp_error( $response ) ) {

				die( 'Request failed. '. $response->get_error_messages() );

			} else {

				return json_decode( $response['body'], true );

			}

		}

		/**
		 * Test authentication token.
		 *
		 * @access public
		 * @return bool
		 */
		function auth_test() {

			return $this->make_request( 'auth.test' );

		}

		/**
		 * Get member from email
		 * @param  string $email The member's email address
		 * @return object        The member details
		 */
		function get_member( $email ) {
			$members = $this->make_request( 'users.list' );
			if (empty($members['ok'])) return false;
			foreach ($members['members'] as $key => $member) {
				if (strcasecmp($member['profile']['email'], $email) === 0) {
					return $member;
				}
			}
		}

		/**
		 * Add a member to a channel
		 * @param  string $member  The Slack member details
		 * @param  string $channel The channel to add them to
		 */
		function add_to_group( $member, $channel ) {
			if (empty($member) || empty($member['id'])) return false;
			return $this->make_request( 'conversations.invite', array( 'channel' => $channel, 'users' => $member['id'] ) );
		}

		/**
		 * Send invitation.
		 *
		 * @access public
		 * @return void
		 */
		function send_invite( $email, $options ) {

			$options = array_merge($options, array( 'email' => $email, 'set_active' => true ));
			return $this->make_request( 'users.admin.invite', $options );

		}
	}