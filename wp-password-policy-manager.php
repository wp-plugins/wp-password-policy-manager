<?php

/*
Plugin Name: WordPress Password Policy Manager
Plugin URI: http://www.wpwhitesecurity.com/wordpress-security-plugins/wordpress-password-policy-manager-plugin/
Description: WordPress Password Policy Manager allows WordPress administrators to configure password policies for WordPress users to use strong passwords.
Author: WP White Security
Version: 0.1
Author URI: http://www.wpwhitesecurity.com/
License: GPL2

    WordPress Password Policy Manager
    Copyright(c) 2014  Robert Abela  (email : robert@wpwhitesecurity.com)

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License, version 2, as
    published by the Free Software Foundation.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

class WpPasswordPolicyManager {
	
	// Session-specific settings determined from hooks
	protected $CurrentPassIsOld = false;
	protected $CurrentUserLogin = false;
	
	const OPT_NAME_TTL = 'wppm_ttl_str';
	const OPT_NAME_UPM = 'wppm_passmod';
	const DEF_TTL      = '10 days';
	const DEF_PFX      = 'wppm';
	
	// <editor-fold desc="Entry Points">
	
	/**
	 * Standard singleton pattern.
	 * @return \self Returns the current plugin instance.
	 */
	public static function GetInstance(){
		static $instance = null;
		if(!$instance)$instance = new self();
		return $instance;
	}
	
	/**
	 * Connect plugin with Wordpress...
	 */
	public function __construct(){
		// no idea why this just doesn't work automatically
		date_default_timezone_set(get_option('timezone_string'));
		
		// register filters
		foreach(array(
			array('wp_authenticate_user', 2),
			array('login_form_middle', 0),
			array('login_head', 0),
			array('password_reset', 2)
		) as $filter){
			list($name, $argc) = $filter;
			add_filter($name, array($this, $name), 10, $argc);
		}
		
		// register actions
		foreach(array(
			array('admin_menu', 0),
			array('user_profile_update_errors', 3),
		) as $filter){
			list($name, $argc) = $filter;
			add_action($name, array($this, $name), 10, $argc);
		}
	}

	// </editor-fold>
	
	// <editor-fold desc="Misc Functionality">
	
	/**
	 * @return string Password policy time to live as a string.
	 */
	public function GetPasswordTtl(){
		$opt = trim(get_option(self::OPT_NAME_TTL, ''));
		return !$opt ? self::DEF_TTL : $opt;
	}
	
	/**
	 * Set new password time-to-live.
	 * @param string $newTtl Password policy time to live as a string.
	 */
	public function SetPasswordTtl($newTtl){
		$time = strtotime($newTtl);
		if($time === false || $time < time())
			throw new Exception('Password policy expiration time is not valid.');
		update_option(self::OPT_NAME_TTL, $newTtl);
	}
	
	/**
	 * Returns whether the password is too old or not.
	 * @param integer $setTime The timestamp of when the password was set.
	 * @return boolean True if old, false otherwise.
	 */
	public function IsPasswordOld($setTime){
		return strtotime($this->GetPasswordTtl(), $setTime) <= time();
	}
	
	/**
	 * Generates some javascript that changes Wordpress' login form.
	 */
	protected function ModifyWpLoginForm(){
		$ver = filemtime(dirname(__FILE__).DIRECTORY_SEPARATOR.'scripts.js');
		$url = plugins_url(basename(dirname(__FILE__)).DIRECTORY_SEPARATOR.'scripts.js');
		wp_enqueue_script(self::DEF_PFX, $url, array('jquery'), $ver);
		?><script type="text/javascript">
			window.wppm_ModifyForm = <?php echo json_encode(array(
				'CurrentUserLogin' => $this->CurrentUserLogin,
				'TextOldPass' => __('Old Password'),
				'TextNewPass' => __('New Password'),
				'TextVerPass' => __('Verify Password'),
				'BtnChangeAndLogin' => __('Change & Log in'),
			)); ?>;
		</script><?php
	}
	
	protected function UpdateWpOptions(){
		if(isset($_POST[self::DEF_PFX.'_ttl']))
			$this->SetPasswordTtl($_POST[self::DEF_PFX.'_ttl']);
	}
	
	/**
	 * Renders Wordpress settings page.
	 */
	public function ManageWpOptions(){
		// control access to plugin
		if ( !current_user_can( 'manage_options' ) )  {
			wp_die( __( 'You do not have sufficient permissions to access this page.' ) );
		}
		
		// update submitted settings
		if(isset($_POST[self::DEF_PFX.'_snt'])){
			try {
				$this->UpdateWpOptions();
				?><div class="updated"><p><strong><?php _e('Settings saved.'); ?></strong></p></div><?php
			} catch (Exception $ex) {
				?><div class="error"><p><strong><?php _e(__('Error').': '.$ex->getMessage()); ?></strong></p></div><?php
			}
		}
		
		// display settings page
		?><div class="wrap">
			<h2><?php echo __( 'WordPress Password Policy Manager Settings'); ?></h2>
			<form method="post" action="">
				<table class="form-table">
					<tbody>
						<tr valign="top">
							<th scope="row"><label for="admin_email"><?php _e('Password Expiration Policy'); ?>  </label></th>
							<td>
								<input type="text" id="<?php echo self::DEF_PFX.'_ttl'; ?>" name="<?php echo self::DEF_PFX.'_ttl'; ?>"
									   value="<?php echo esc_attr($this->GetPasswordTtl()); ?>" size="20" class="regular-text ltr">
								<p class="description">Examples: <code>5 days</code> <code>20 days 6 hours</code> <code>3 weeks</code></p>
							</td>
						</tr>
					</tbody>
				</table>
				<p class="submit">
					<input type="submit" name="<?php echo self::DEF_PFX.'_snt'; ?>" class="button-primary" value="<?php esc_attr_e('Save Changes') ?>" />
				</p>
			</form>
		</div><?php
	}
	
	/**
	 * Returns whether password for specified user is too old or not.
	 * @param WP_User|integer $userOrUid Either user instance or user id.
	 * @return boolean True if the password is old.
	 */
	public function IsUserPasswordOld($userOrUid){
		return $this->IsPasswordOld($this->GetPasswordLastModTime(is_object($userOrUid) ? $userOrUid->ID : $userOrUid));
	}
	
	/**
	 * Returns the last modification date of a user's password.
	 * @param integer $user_ID The user's id.
	 * @return integer Timestamp.
	 */
	public function GetPasswordLastModTime($user_ID){
		$time = (int)get_user_option(self::OPT_NAME_UPM, $user_ID);
		if(!$time)$time = strtotime(get_userdata($user_ID)->user_registered);
		return $time;
	}
	
	// </editor-fold>
	
	// <editor-fold desc="Wordpress Hooks and Filters">
	
	public function login_head(){
		// this is to affect wp-login.php
		if($this->CurrentPassIsOld)$this->ModifyWpLoginForm();
	}
	
	public function login_form_middle(){
		// this is to affect wp_login_form()
		if($this->CurrentPassIsOld)$this->ModifyWpLoginForm();
	}
	
	public function wp_authenticate_user($user, $password) {
		if($user instanceof WP_User && wp_check_password($password, $user->data->user_pass, $user->ID) && $this->IsUserPasswordOld($user)){
			
			// this data is used in the login form later on...
			$this->CurrentPassIsOld = true;
			$this->CurrentUserLogin = $user->user_login;
			
			if(isset($_REQUEST['user_pass_new']) && isset($_REQUEST['user_pass_vfy'])){
					
				if(!trim($_REQUEST['user_pass_new']) || !trim($_REQUEST['user_pass_vfy']))
					return new WP_Error('expired_password', __('<strong>ERROR</strong>: The new password cannot be empty.'));
				if($_REQUEST['user_pass_new'] != $_REQUEST['user_pass_vfy'])
					return new WP_Error('expired_password', __('<strong>ERROR</strong>: Both new passwords must match.'));
				if($_REQUEST['user_pass_new'] == $password)
					return new WP_Error('expired_password', __('<strong>ERROR</strong>: New password cannot be the same as the old one.'));
				if($_REQUEST['user_pass_new'] == $user->user_login)
					return new WP_Error('expired_password', __('<strong>ERROR</strong>: New password cannot be the same as the username.'));
				if($_REQUEST['user_pass_new'] == $user->user_email)
					return new WP_Error('expired_password', __('<strong>ERROR</strong>: New password cannot be the same as the email.'));
				
				wp_set_password($_REQUEST['user_pass_new'], $user->ID);
				$this->password_reset($user, $_REQUEST['user_pass_new']);
				do_action('edit_user_profile_update', $user->ID);
				
				return $user;
				
			}else{
				
				$diff = human_time_diff(strtotime($this->GetPasswordTtl(), $this->GetPasswordLastModTime($user->ID)), time());
				return new WP_Error('expired_password', sprintf(__('<strong>ERROR</strong>: The password you entered expired %1$s ago.'), $diff));
				
			}
		}
		
		return $user;
	}
	
	public function password_reset($user/*, $new_pass*/){
		update_user_option($user->ID, self::OPT_NAME_UPM, time());
	}
	
	public function user_profile_update_errors($errors, $update, $user){
		if (!$errors->get_error_data('pass') && !$errors->get_error_data('expired_password'))
			update_user_option($user->ID, self::OPT_NAME_UPM, time());
	}
	
	public function admin_menu(){
		add_options_page('Password Policy', 'Password Policy', 'manage_options', 'password_policy_settings', array($this, 'ManageWpOptions'));
	}
	
	// </editor-fold>
	
}

// Create & Run the plugin
return WpPasswordPolicyManager::GetInstance();
