<?php
/*
Plugin Name: WP SHA1
Plugin URI: http://www.brunosou.com
Description: Authenticate SHA1 passwords too.
Version: 1.0
Author: Bruno Sousa
Author URI: http://www.brunosou.com
License: GPL
*/

 /* is_sha1 METHOD - Validate SHA1
	- Return true or false
 */
function is_sha1($str) {
    return (bool) preg_match('/^[0-9a-f]{40}$/i', $str);
}

 /* is_md5 METHOD - Validate md5
	- Return true or false
 */
function is_md5($str) {
	return (bool) preg_match('/^[0-9a-f]{32}$/i', $str);
}



 /* CUSTOM PASSWORD METHOD - Accept SHA1
	- Return user
 */

function checkme($ha1, $password, $hash) {
	global $wp_hasher;

	// If the hash is sha1...
	if ( is_sha1($hash) ) {
		$check = ( $hash == sha1($password) );
		if ( $check && $user_id ) {
			// Rehash using new hash.
			wp_set_password($password, $user_id);
			$hash = wp_hash_password($password);
		}

		return apply_filters('checkme', $check, $password, $hash, $user_id);
	}
	
	// If the hash is still md5...
	if ( is_md5($hash) ) {
		$check = ( $hash == md5($password) );
		if ( $check && $user_id ) {
			// Rehash using new hash.
			wp_set_password($password, $user_id);
			$hash = wp_hash_password($password);
		}

		return apply_filters('checkme', $check, $password, $hash, $user_id);
	}

	// If the stored hash is longer than an MD5, presume the
	// new style phpass portable hash.
	if ( empty($wp_hasher) ) {
		require_once( ABSPATH . 'wp-includes/class-phpass.php');
		// By default, use the portable hash from phpass
		$wp_hasher = new PasswordHash(8, TRUE);
	}

	$check = $wp_hasher->CheckPassword($password, $hash);

	return apply_filters('checkme', $check, $password, $hash, $user_id);

}

add_filter('check_password', 'checkme', 10, 3);
?>