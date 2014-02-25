<?php

/*
Plugin Name: WP Password Policy Manager
Plugin URI: http://www.wpwhitesecurity.com/wordpress-security-plugins/wp-password-policy-manager/
Description: Ensure the security of your WordPress by forcing users to use strong passwords by configuring WordPress password policies.
Author: WP White Security
Version: 0.2
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
	
	// <editor-fold desc="Constants">
	
	// Session-specific settings determined from hooks
	protected $CurrentPassIsOld = false;
	protected $CurrentUserLogin = false;
	
	const DEF_PFX      = 'wppm';
	
	const PLG_CONFIG_MENU_NAME = 'password_policy_settings';
	
	const OPT_NAME_UPM = 'wppm_passmod';
	
	const OPT_NAME_TTL = 'wppm_ttl_str';
	const OPT_NAME_LEN = 'wppm_len_int';
	const OPT_NAME_BIT = 'wppm_pol_bit';
	
	const POLICY_MIXCASE = 'C';
	const POLICY_NUMBERS = 'N';
	const POLICY_SPECIAL = 'S';
	
	const DEF_OPT_TTL  = '';
	const DEF_OPT_LEN  = 0;
	const DEF_OPT_CPT  = false;
	const DEF_OPT_NUM  = false;
	const DEF_OPT_SPL  = false;
	
	// </editor-fold>
	
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
			array('admin_enqueue_scripts', 0),
			array('admin_print_footer_scripts', 0),
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
		return !$opt ? self::DEF_OPT_TTL : $opt;
	}
	
	/**
	 * @return integer Password length policy (0=disabled).
	 */
	public function GetPasswordLen(){
		return (int)get_option(self::OPT_NAME_LEN, self::DEF_OPT_LEN);
	}
	
	/**
	 * Set new password time-to-live.
	 * @param string $newTtl Password policy time to live as a string.
	 */
	public function SetPasswordTtl($newTtl){
		if(trim($newTtl)){
			$time = strtotime($newTtl);
			if($time === false || $time < time())
				throw new Exception('Password policy expiration time is not valid.');
		}else $newTtl = '';
		update_option(self::OPT_NAME_TTL, $newTtl);
	}
	
	/**
	 * @param integer Password length policy (0=disable policy).
	 */
	public function SetPasswordLen($length){
		update_option(self::OPT_NAME_LEN, $length);
	}
	
	protected $_policy_flag_cache = null;
	
	/**
	 * Returns password policy bitfield.
	 * @return string Policy bitfield.
	 */
	public function GetPolicyFlags(){
		if(is_null($this->_policy_flag_cache))
			$this->_policy_flag_cache = get_option(self::OPT_NAME_BIT, '');
		return $this->_policy_flag_cache;
	}
	
	/**
	 * Checks whether a policy is enabled or not.
	 * @param string $policy Any of the POLICY_* constants.
	 * @return boolean True if enabled, false otherwise.
	 */
	public function IsPolicyEnabled($policy){
		return strpos($this->GetPolicyFlags(), $policy) !== false;
	}
	
	/**
	 * Enables or disables a particular policy.
	 * @param integer $policy Any of the POLICY_* constants.
	 * @param boolean $enabled True to enable policy, false otherwise.
	 */
	public function SetPolicyState($policy, $enabled){
		$flags = str_replace($policy, '', $this->GetPolicyFlags());
		if($enabled)$flags .= $policy;
		update_option(self::OPT_NAME_BIT, $flags);
		$this->_policy_flag_cache = null; // clear cache
	}
	
	/**
	 * Returns whether the password is too old or not.
	 * @param integer $setTime The timestamp of when the password was set.
	 * @return boolean True if old, false otherwise.
	 */
	public function IsPasswordOld($setTime){
		$ttl = $this->GetPasswordTtl();
		if(!trim($ttl))return false;
		return strtotime($ttl, $setTime) <= time();
	}
	
	/**
	 * Generates some javascript that changes Wordpress' login form.
	 */
	protected function ModifyWpLoginForm(){
		$ver = filemtime(dirname(__FILE__).DIRECTORY_SEPARATOR.'scripts.js');
		$url = plugins_url(basename(dirname(__FILE__)).DIRECTORY_SEPARATOR.'scripts.js');
		
		$rules = array(
			__('not be the same as your username'),
			__('not be the same as the previous one'),
		);
		if(!!($c = $this->GetPasswordLen()))
			$rules[] = sprintf(__('be at least %d characters long'), $c);
		if($this->IsPolicyEnabled(self::POLICY_MIXCASE))
			$rules[] = sprintf(__('contain mixed case characters'));
		if($this->IsPolicyEnabled(self::POLICY_NUMBERS))
			$rules[] = sprintf(__('contain numeric digits'));
		if($this->IsPolicyEnabled(self::POLICY_SPECIAL))
			$rules[] = sprintf(__('contain special characters'));
		
		wp_enqueue_script(self::DEF_PFX, $url, array('jquery'), $ver);
		?><script type="text/javascript">
			window.wppm_ModifyForm = <?php echo json_encode(array(
				'CurrentUserLogin' => $this->CurrentUserLogin,
				'CurrentUserPass' => isset($_REQUEST['pwd']) ? $_REQUEST['pwd'] : '',
				'TextOldPass' => __('Old Password'),
				'TextNewPass' => __('New Password'),
				'TextVerPass' => __('Verify Password'),
				'BtnChangeAndLogin' => __('Change & Log in'),
				'NewPasswordRules' => $rules,
				'NewPassRulesHead' => __('New password must...'),
				'NewPassRulesFoot' => __('WordPress Password Policies by')
					.'<br/><a href="http://www.wpwhitesecurity.com/wordpress-security-plugins/wp-password-policy-manager/" target="_blank">WP Password Policy Manager</a>',
			)); ?>;
		</script><?php
	}
	
	protected function EchoIdent($name){
		echo self::DEF_PFX.'_'.$name;
	}
	
	protected function IsPostIdent($name){
		return isset($_POST[self::DEF_PFX.'_'.$name]);
	}
	
	protected function IsJustInstalled(){
		return (get_option(self::OPT_NAME_TTL, null) === null)
			|| (get_option(self::OPT_NAME_LEN, null) === null);
	}
	
	protected function GetPostIdent($name){
		return $_POST[self::DEF_PFX.'_'.$name];
	}
	
	protected function UpdateWpOptions(){
		if($this->IsPostIdent('ttl'))
			$this->SetPasswordTtl($this->GetPostIdent('ttl'));
		if($this->IsPostIdent('len'))
			$this->SetPasswordLen($this->GetPostIdent('len'));
		$this->SetPolicyState(self::POLICY_MIXCASE, $this->IsPostIdent('cpt'));
		$this->SetPolicyState(self::POLICY_NUMBERS, $this->IsPostIdent('num'));
		$this->SetPolicyState(self::POLICY_SPECIAL, $this->IsPostIdent('spc'));
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
							<th scope="row"><label for="<?php $this->EchoIdent('ttl'); ?>"><?php _e('Password Expiration Policy'); ?></label></th>
							<td>
								<input type="text" id="<?php $this->EchoIdent('ttl'); ?>" name="<?php $this->EchoIdent('ttl'); ?>"
									   value="<?php echo esc_attr($this->GetPasswordTtl()); ?>" size="20" class="regular-text ltr">
								<p class="description">Examples: <code>5 days</code> <code>20 days 6 hours</code> <code>3 weeks</code></p>
								Leave blank to disable Password Expiry policy
							</td>
						</tr>
						<tr valign="top">
							<th scope="row"><label for="<?php $this->EchoIdent('len'); ?>"><?php _e('Password Length Policy'); ?></label></th>
							<td>
								<select type="text" id="<?php $this->EchoIdent('len'); ?>" name="<?php $this->EchoIdent('len'); ?>"><?php
									$curr = $this->GetPasswordLen();
									foreach(array_merge(array(0), range(4, 16)) as $value){
										$sel = ($value == $curr) ? ' selected="selected"' : '';
										?><option value="<?php echo $value; ?>"<?php echo $sel; ?>>
											<?php echo ($value == 0 ? '' : $value); ?>
										</option><?php
									}
								?></select> characters<br/>
								Leave blank to disable Password Length policy
							</td>
						</tr>
						<tr valign="top">
							<th scope="row"><label for="<?php $this->EchoIdent('cpt'); ?>"><?php _e('Mixed Case Policy'); ?></label></th>
							<td>
								<fieldset>
									<legend class="screen-reader-text"><span><?php _e('Mixed Case Policy'); ?></span></legend>
									<label for="<?php $this->EchoIdent('cpt'); ?>">
										<input name="<?php $this->EchoIdent('cpt'); ?>" type="checkbox" id="<?php $this->EchoIdent('cpt'); ?>"
											   value="1"<?php if($this->IsPolicyEnabled(self::POLICY_MIXCASE))echo ' checked="checked"'; ?>/>
										Password must contain a mix of uppercase and lowercase characters.
									</label>
								</fieldset>
							</td>
						</tr>
						<tr valign="top">
							<th scope="row"><label for="<?php $this->EchoIdent('num'); ?>"><?php _e('Numeric Digits Policy'); ?></label></th>
							<td>
								<fieldset>
									<legend class="screen-reader-text"><span><?php _e('Numeric Digits Policy'); ?></span></legend>
									<label for="<?php $this->EchoIdent('num'); ?>">
										<input name="<?php $this->EchoIdent('num'); ?>" type="checkbox" id="<?php $this->EchoIdent('num'); ?>"
											   value="1"<?php if($this->IsPolicyEnabled(self::POLICY_NUMBERS))echo ' checked="checked"'; ?>/>
										Password must contain numeric digits (<code>0-9</code>).
									</label>
								</fieldset>
							</td>
						</tr>
						<tr valign="top">
							<th scope="row"><label for="<?php $this->EchoIdent('spc'); ?>"><?php _e('Special Characters Policy'); ?></label></th>
							<td>
								<fieldset>
									<legend class="screen-reader-text"><span><?php _e('Special Characters Policy'); ?></span></legend>
									<label for="<?php $this->EchoIdent('spc'); ?>">
										<input name="<?php $this->EchoIdent('spc'); ?>" type="checkbox" id="<?php $this->EchoIdent('spc'); ?>"
											   value="1"<?php if($this->IsPolicyEnabled(self::POLICY_SPECIAL))echo ' checked="checked"'; ?>/>
										Password must contain special characters (eg: <code>.,!#$_+</code>).
									</label>
								</fieldset>
							</td>
						</tr>
					</tbody>
				</table>
				<!-- Policy Flags: <?php echo $this->_policy_flag_cache; ?> -->
				<p class="submit">
					<input type="submit" name="<?php $this->EchoIdent('snt'); ?>" class="button-primary" value="<?php esc_attr_e('Save Changes') ?>" />
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
				if(($c = $this->GetPasswordLen()) != 0)
					if(strlen($_REQUEST['user_pass_new']) < $c)
						return new WP_Error('expired_password', sprintf(__('<strong>ERROR</strong>: New password must contain at least %d characters.'), $c));
				if($this->IsPolicyEnabled(self::POLICY_MIXCASE))
					if(strtolower($_REQUEST['user_pass_new']) == $_REQUEST['user_pass_new'])
						return new WP_Error('expired_password', __('<strong>ERROR</strong>: New password must contain both uppercase and lowercase characters.'));
				if($this->IsPolicyEnabled(self::POLICY_NUMBERS))
					if(!preg_match('/[0-9]/', $_REQUEST['user_pass_new']))
						return new WP_Error('expired_password', __('<strong>ERROR</strong>: New password must contain numbers.'));
				if($this->IsPolicyEnabled(self::POLICY_SPECIAL))
					if(!preg_match('/[_\W]/', $_REQUEST['user_pass_new']))
						return new WP_Error('expired_password', __('<strong>ERROR</strong>: New password must contain special characters.'));
				
				wp_set_password($_REQUEST['user_pass_new'], $user->ID);
				$this->password_reset($user, $_REQUEST['user_pass_new']);
				do_action('edit_user_profile_update', $user->ID);
				
				return $user;
				
			}else{
				
				$diff = human_time_diff(strtotime($this->GetPasswordTtl(), $this->GetPasswordLastModTime($user->ID)), time());
				return new WP_Error('expired_password', sprintf(__('<strong>ERROR</strong>: The password you entered expired %s ago.'), $diff));
				
			}
		}
		
		return $user;
	}
	
	public function password_reset($user/*, $new_pass*/){
		update_user_option($user->ID, self::OPT_NAME_UPM, time());
	}
	
	public function user_profile_update_errors($errors, $update, $user){
		$update = $update; // stops IDE from complaining -_-
		if (!$errors->get_error_data('pass') && !$errors->get_error_data('expired_password'))
			update_user_option($user->ID, self::OPT_NAME_UPM, time());
	}
	
	public function admin_menu(){
		add_options_page('Password Policies', 'Password Policies', 'manage_options', self::PLG_CONFIG_MENU_NAME, array($this, 'ManageWpOptions'));
	}
	
	public function admin_enqueue_scripts(){
		if($this->IsJustInstalled()){
			wp_enqueue_style('wp-pointer');
			wp_enqueue_script('wp-pointer');
		}
	}
	
	public function admin_print_footer_scripts(){
		$isOnPluginPage = isset($_REQUEST['page']) && $_REQUEST['page']==self::PLG_CONFIG_MENU_NAME;
		
		if($this->IsJustInstalled() && !$isOnPluginPage){
			$tle = __('Configure Password Policies');
			$txt = __('You have just installed WP Password Policy manager. All password policies are disabled by default. Click the button below to configure the WordPress password policies.');
			$btn = __('Configure Policies');
			$url = admin_url('options-general.php?page='.self::PLG_CONFIG_MENU_NAME);
			?><script type="text/javascript">
				jQuery(document).ready(function($) {
					$('#wp-admin-bar-my-account').pointer({
						buttons: function () {
							return jQuery(<?php echo json_encode(
								"<a class='button-primary' href=\"$url\">$btn</a>"
							); ?>);
						},
						'content': <?php echo json_encode(
							"<h3>$tle</h3><p>$txt</p>"
						); ?>
					}).pointer('open');
				});
			</script><?php
		}
	}
	
	// </editor-fold>
	
}

// Create & Run the plugin
return WpPasswordPolicyManager::GetInstance();
