<?php

	// Security
	if (!defined('ABSPATH')) exit;


	/**
	 * Display custom user account management fields
	 * @param  Object $user The user data
	 */
	function gmt_courses_validate_user_field ( $user ) {

		?>
		<h3><?php _e('Courses Account Management', 'gmt_courses'); ?></h3>
		<table class="form-table">
			<tbody>
				<tr>
					<th><?php _e('Validate Account', 'gmt_courses'); ?></th>
					<td>
						<label for="gmt_courses_validate_user">
							<input type="checkbox" name="gmt_courses_validate_user" id="gmt_courses_validate_user">
							<?php _e('Validate the user', 'gmt_courses'); ?>
						</label>
					</td>
				</tr>
			</tbody>
		</table>
		<?php

	}
	add_action( 'show_user_profile', 'gmt_courses_validate_user_field', 10 );
	add_action( 'edit_user_profile', 'gmt_courses_validate_user_field', 10 );



	/**
	 * Validate the user account
	 * @param  Integer $user_id The user ID
	 */
	function gmt_courses_process_validate_user ( $user_id ) {

		if ( !current_user_can( 'edit_user', $user_id ) ) return false;

		if (isset($_POST['gmt_courses_validate_user'])) {
			delete_user_meta($user_id, 'user_validation_key');
		}

	}
	add_action( 'personal_options_update', 'gmt_courses_process_validate_user' );
	add_action( 'edit_user_profile_update', 'gmt_courses_process_validate_user' );