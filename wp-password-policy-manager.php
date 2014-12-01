<?php
/*
Plugin Name: WordPress Password Policy Manager
Plugin URI: http://www.wpwhitesecurity.com/wordpress-security-plugins/wordpress-password-policy-manager-plugin/
Description: WordPress Password Policy Manager allows WordPress administrators to configure password policies for WordPress users to use strong passwords.
Author: WP White Security
Version: 0.4
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

class WpPasswordPolicyManager
{
    // <editor-fold desc="Constants">
    // Session-specific settings determined from hooks
    protected $CurrentPassIsOld = false;
    protected $CurrentUserLogin = false;
    const DEF_PFX = 'wppm';
    const PLG_CONFIG_MENU_NAME = 'password_policy_settings';
    const OPT_NAME_UPM = 'wppm_passmod';
    const OPT_NAME_TTL = 'wppm_ttl_str';
    const OPT_NAME_LEN = 'wppm_len_int';
    const OPT_NAME_BIT = 'wppm_pol_bit';
    const OPT_NAME_XMT = 'wppm_xmt_lst';
    const OPT_NAME_MSP = 'wppm_msp_int';
    const OPT_NAME_OPL = 'wppm_opl_lst';
    const POLICY_MIXCASE = 'C';
    const POLICY_NUMBERS = 'N';
    const POLICY_SPECIAL = 'S';
    const DEF_OPT_TTL = '';
    const DEF_OPT_LEN = 0;
    const DEF_OPT_CPT = false;
    const DEF_OPT_NUM = false;
    const DEF_OPT_SPL = false;
    const OPT_USER_PWDS = 'wppm_lst_pwd';
    const OPT_USER_RST_PWD = 'wppm_rst_pwd';

    // </editor-fold>

// <editor-fold desc="Entry Points">
    private function __construct(){
        // register actions
        foreach(array(
                    array('admin_menu', 0),
                    array('network_admin_menu', 0),
                    array('admin_enqueue_scripts', 0),
                    array('admin_footer', 0),
                    array('admin_print_footer_scripts', 0),
                    array('wp_ajax_check_security_token', 0),
                    array('profile_update', 2),
                    array('user_profile_update_errors', 3),
                    array('user_register', 1),
                ) as $filter){
            list($name, $argc) = $filter;
            $cb = isset($filter[2]) ? $filter[2] : array($this, $name);
            add_action($name, $cb, 10, $argc);
        }
        //-- wp internals
        add_filter('plugin_action_links_'.$this->GetBaseName(), array($this, 'plugin_action_links'), 10, 1);
        add_filter('password_reset', array($this, 'password_reset'), 10, 2);
        //-- login
        add_filter('wp_authenticate_user', array($this, 'ValidateLoginForm'), 10, 2);
        add_action('login_form', array($this, 'ModifyLoginForm'), 10, 2);
        //-- user profile
        add_action( 'show_user_profile', array($this, 'ModifyUserProfilePage')); // user -> own profile
        add_action( 'edit_user_profile', array($this, 'ModifyUserProfilePage')); // admin -> user profile
        add_action( 'user_profile_update_errors', array( $this, 'ValidateUserProfilePage' ), 0, 3 );
        //-- pwd reset
        add_action( 'validate_password_reset', array($this,'ValidatePasswordReset'), 10, 2 );
        add_action( 'validate_password_reset', array($this,'ModifyWpResetForm'), 10);
    }

    /**
     * Standard singleton pattern.
     * @return \self Returns the current plugin instance.
     */
    public static function GetInstance()
    {
        static $instance = null;
        if (!$instance) $instance = new self();
        return $instance;
    }
    // </editor-fold>


    // <editor-fold desc="WP Internals">

    protected function GetPasswordRules(){
        $rules = array(
            __('not be the same as your username'),
        );
        $_nMaxSamePass = $this->GetMaxSamePass();
        if ($_nMaxSamePass) {
            $rules[] = sprintf(__('not be one of the previous %d used passwords.'), $_nMaxSamePass);
        } else {
            $rules[] = __('not be the same as the previous one');
        }

        if (!!($c = $this->GetPasswordLen()))
            $rules[] = sprintf(__('be at least %d characters long'), $c);
        if ($this->IsPolicyEnabled(self::POLICY_MIXCASE))
            $rules[] = sprintf(__('contain mixed case characters'));
        if ($this->IsPolicyEnabled(self::POLICY_NUMBERS))
            $rules[] = sprintf(__('contain numeric digits'));
        if ($this->IsPolicyEnabled(self::POLICY_SPECIAL))
            $rules[] = sprintf(__('contain special characters'));
        return $rules;
    }

    protected $pwd = '';
    function ModifyLoginForm(){
        if(!empty($this->CurrentUserLogin)){
            $username = $this->CurrentUserLogin;
            if (!username_exists($username)) {
                return;
            }
        }
        else {
            $username = (isset($_REQUEST['log'])&&!empty($_REQUEST['log']) ? $_REQUEST['log'] : '');
            if(empty($username)){
                return;
            }
        }

        if(!empty($this->pwd)){
            $password = $this->pwd;
        }
        else {
            $password = isset($_REQUEST['pwd']) ? stripslashes($_REQUEST['pwd']) : '';
            if(empty($password)){
                return;
            }
        }

        $user = new WP_User($username);
        if($this->IsUserExemptFromPolicies($user)){
            // policies do not apply in this case
            return;
        }
        if(!$this->IsUserPasswordOld($user)){
            if(!wp_check_password($password, $user->data->user_pass, $user->ID)){
                // let WP handle this
                return;
            }
        }
        ?>
        <p>
            <label for="user_pass_new"><?php _e('New Password') ?><br />
                <input type="password" name="user_pass_new" id="user_pass_new" class="input" value="<?php echo ''; ?>" size="25" /></label>
        </p>
        <p>
            <label for="user_pass_vfy"><?php _e('Verify Password') ?><br />
                <input type="password" name="user_pass_vfy" id="user_pass_vfy" class="input" value="<?php echo ''; ?>" size="25" /></label>
        </p>
        <script type="text/javascript">
            window.wppm_ModifyForm = <?php echo json_encode(array(
                'CurrentUserLogin' => $username,
                'CurrentUserPass' => $password,
                'TextOldPass' => __('Old Password'),
                'BtnChangeAndLogin' => __('Change & Log in'),
                'NewPasswordRules' => $this->GetPasswordRules(),
                'NewPassRulesHead' => __('New password must...'),
                'NewPassRulesFoot' => __('WordPress Password Policies by')
                    . '<br/><a href="http://www.wpwhitesecurity.com/wordpress-security-plugins/wp-password-policy-manager/" target="_blank">'
                        . __('WP Password Policy Manager')
                    . '</a>'
            )); ?>;
        </script><?php
        wp_enqueue_script('front-js', $this->GetBaseUrl().'js/front.js', array('jquery'), rand(1,1234));
    }

    protected $shouldModify = false;
    public function ValidateLoginForm($user, $password){
        if(!($user instanceof WP_User)){
            return new WP_Error('expired_password', __('Invalid Request'));
        }
        if($this->IsUserExemptFromPolicies($user)){
            return $user;
        }
        $wasReset = (bool)absint($this->GetGlobalOption(self::OPT_USER_RST_PWD.'_'.$user->ID));

        if(wp_check_password($password, $user->data->user_pass, $user->ID) && ($wasReset || $this->IsUserPasswordOld($user)))
        {
            $this->CurrentPassIsOld = true;
            $this->CurrentUserLogin = $user->user_login;

            $this->pwd = stripslashes($password);
            $this->shouldModify = true;

            // Apply password policies
            if(isset($_REQUEST['user_pass_new']) && isset($_REQUEST['user_pass_vfy'])){
                if(!trim($_REQUEST['user_pass_new']) || !trim($_REQUEST['user_pass_vfy']))
                    return new WP_Error('expired_password', __('<strong>ERROR</strong>: The new password cannot be empty.'));
                if($_REQUEST['user_pass_new'] != $_REQUEST['user_pass_vfy'])
                    return new WP_Error('expired_password', __('<strong>ERROR</strong>: Both new passwords must match.'));
                if(wp_check_password($_REQUEST['user_pass_new'], $user->data->user_pass, $user->ID))
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
                // update user passwords, if the policy applies
                $_nMaxSamePass = $this->GetMaxSamePass();
                if($_nMaxSamePass){
                    if($this->_pwdHasBeenUsed($user->ID, $_REQUEST['user_pass_new'])){
                        return new WP_Error('expired_password',
                            sprintf(__('<strong>ERROR</strong>: New password must not be one of the previous %d used passwords.'), $_nMaxSamePass));
                    }
                    $this->_addPwdToList($user->ID, $_REQUEST['user_pass_new']);
                }
                else {self::ClearUserPrevPwds($user->ID); }

                wp_set_password($_REQUEST['user_pass_new'], $user->ID);
                $this->password_reset($user, $_REQUEST['user_pass_new']);
                do_action('edit_user_profile_update', $user->ID);
                // Check if the user's pwd had been reset
                if($wasReset) {
                    $this->DeleteGlobalOption(self::OPT_USER_RST_PWD . '_' . $user->ID);
                }
                return $user;
            }
            else{
                if($wasReset){
                    $diff = __('1 minute');
                }
                else { $diff = human_time_diff(strtotime($this->GetPasswordTtl(), $this->GetPasswordLastModTime($user->ID)), current_time('timestamp')); }
                return new WP_Error('expired_password', sprintf(__('<strong>ERROR</strong>: The password you entered expired %s ago.'), $diff));
            }
        }
        return $user;
    }

    public function ModifyUserProfilePage($user=null){
        $rules = $this->GetPasswordRules();
        ?>
        <table class="form-table">
            <tr>
                <th><label><?php _e('New password must') ;?></label></th>
                <td>
                    <div id="wppmUserProfilePwdRulesContainer">
                        <ul style="list-style: disc inside; margin-top: 5px;">
                            <?php foreach($rules as $item) { echo "<li>{$item}</li>"; } ?>
                        </ul>
                        <div style="width: 240px;">
                            <p style="text-align: center;"><?php echo
                                    __('WordPress Password Policies by')
                                    . '<br/><a href="http://www.wpwhitesecurity.com/wordpress-security-plugins/wp-password-policy-manager/" target="_blank">'
                                    . __('WP Password Policy Manager'). '</a>'
                                ?></p>
                        </div>
                    </div>
                </td>
            </tr>
        </table>
    <?php }

    public function ValidateUserProfilePage($errors, $update = null, $user = null){
        $pass1 = (isset($_REQUEST['pass1']) ? $_REQUEST['pass1'] : '');
        $pass2 = (isset($_REQUEST['pass2']) ? $_REQUEST['pass2'] : '');
        return $this->__validateProfile($errors, $user, $pass1, $pass2);
    }

    /**
     * Validates the User profile page
     * @internal
     * @param $errors
     * @param $user
     * @param $pass1
     * @param $pass2
     * @return mixed
     */
    protected function __validateProfile($errors, $user, $pass1, $pass2){
        if($user){
            if(! isset($user->ID)){
                return $errors;
            }
            $_user = null;
            if(!($user instanceof WP_User) && $user instanceof stdClass){
                $_user = new WP_User($user->ID);
                $user = $_user;
            }
        }
        else { return $errors; }
        $userInfo = $user->data;

        if(!$this->IsUserExemptFromPolicies($user))
        {
            // If the user updates their password, it should comply with the policies
            if((isset($pass1) && isset($pass2)) && (!empty($pass1) && !empty($pass2)))
            {
                if(empty($pass1) || empty($pass2)){
                    $errors->add('expired_password', '<strong>ERROR</strong>: The new password cannot be empty.');
                    return $errors;
                }
                if($pass1 <> $pass2){
                    $errors->add('expired_password', '<strong>ERROR</strong>: Both new passwords must match.');
                    return $errors;
                }
                // get the current pass
                $crtPwd = $userInfo->user_pass;
                if(wp_check_password($pass1, $crtPwd, $user->ID)){
                    $errors->add('expired_password', '<strong>ERROR</strong>: New password cannot be the same as the old one.');
                    return $errors;
                }
                // new password cannot be the same as the username
                if($pass1 == $userInfo->user_login){
                    $errors->add('expired_password', '<strong>ERROR</strong>: New password cannot be the same as the username.');
                    return $errors;
                }
                // new password cannot be the same as the email
                if($pass1 == $userInfo->user_email){
                    $errors->add('expired_password', '<strong>ERROR</strong>: New password cannot be the same as the email.');
                    return $errors;
                }
                // Apply password policies
                if(($c = $this->GetPasswordLen()) != 0) {
                    if (strlen($pass1) < $c) {
                        $errors->add('expired_password', sprintf(__('<strong>ERROR</strong>: New password must contain at least %d characters.'), $c));
                        return $errors;
                    }
                }
                if($this->IsPolicyEnabled(self::POLICY_MIXCASE)) {
                    if (strtolower($pass1) == $pass1) {
                        $errors->add('expired_password', __('<strong>ERROR</strong>: New password must contain both uppercase and lowercase characters.'));
                        return $errors;
                    }
                }
                if($this->IsPolicyEnabled(self::POLICY_NUMBERS)) {
                    if (!preg_match('/[0-9]/', $pass1)) {
                        $errors->add('expired_password', __('<strong>ERROR</strong>: New password must contain numbers.'));
                        return $errors;
                    }
                }
                if($this->IsPolicyEnabled(self::POLICY_SPECIAL)) {
                    if (!preg_match('/[_\W]/', $pass1)) {
                        $errors->add('expired_password', __('<strong>ERROR</strong>: New password must contain special characters.'));
                        return $errors;
                    }
                }
                $_nMaxSamePass = $this->GetMaxSamePass();
                if($_nMaxSamePass){
                    if($this->_pwdHasBeenUsed($user->ID, $pass1)){
                        $errors->add('expired_password',
                            sprintf(__('<strong>ERROR</strong>: New password must not be one of the previous %d used passwords.'), $_nMaxSamePass));
                        return $errors;
                    }
                    $this->_addPwdToList($user->ID, $pass1);
                }
                else {self::ClearUserPrevPwds($user->ID); }

                // if this is not own profile - reset & expire pwd
//                $crtUserID = get_current_user_id();
//                if($crtUserID != $user->ID){
//                    $this->SetGlobalOption(self::OPT_USER_RST_PWD . '_' . $user->ID, true);
//                    update_user_option($user->ID, self::OPT_NAME_UPM, current_time('timestamp'));
//                }
                //----
                $this->SetGlobalOption(self::OPT_USER_RST_PWD . '_' . $user->ID, false);
                update_user_option($user->ID, self::OPT_NAME_UPM, current_time('timestamp')+(strtotime($this->GetPasswordTtl())));
            }
        }
        return $errors;
    }

    public function ModifyWpResetForm() {
        $fp = $this->GetBaseDir().'js/wppmpp.tmp.js';
        if(is_file($fp)){
            if(!@unlink($fp)){
                file_put_contents($fp,'');
            }
        }
        wp_enqueue_style('wppm-reset-css', $this->GetBaseUrl() . 'css/wppm-reset.css', null, filemtime($this->GetBaseDir() . 'css/wppm-reset.css'));
        wp_enqueue_script('wppm-reset-js', $this->GetBaseUrl() . 'js/reset.js', array('jquery'), filemtime($this->GetBaseDir() . 'js/reset.js'));
        //#!-- Because we cannot just echo the script into the page, we're creating a temp js file to hold this setting
        //#!-- and include it into the page using WP's functionality.
        //#!-- this temp js file will be overwritten each time the password policies change
        $str = 'window.wppm_ModifyForm=';
        $str .= json_encode(array(
            'NewPasswordRules' => $this->GetPasswordRules(),
            'NewPassRulesHead' => __('New password must...'),
            'NewPassRulesFoot' => __('WordPress Password Policies by')
                . '<br/><a href="http://www.wpwhitesecurity.com/wordpress-security-plugins/wp-password-policy-manager/" target="_blank">'
                . __('WP Password Policy Manager')
                . '</a>'
        ));
        $str .= ';';
        file_put_contents($this->GetBaseDir().'js/wppmpp.tmp.js', $str);
        wp_enqueue_script('wppm-pwd-policies-js', $this->GetBaseUrl() . 'js/wppmpp.tmp.js', array('jquery'), filemtime($this->GetBaseDir() . 'js/wppmpp.tmp.js'));
    }

    public function ValidatePasswordReset( WP_Error $errors, $user ) {
        $rm = strtoupper($_SERVER['REQUEST_METHOD']);
        if ('POST' == $rm) {
            if (!isset($_POST['pass1']) || !isset($_POST['pass2'])) {
                $errors->add('expired_password', __('The form is not valid. Please refresh the page and try again.'));
                return $errors;
            }
            if (empty($_POST['pass1'])) {
                $errors->add('expired_password', __('Please provide your new password.'));
                return $errors;
            }
            if (empty($_POST['pass2'])) {
                $errors->add('expired_password', __('Please confirm your new password.'));
                return $errors;
            }

            $password = trim(strip_tags($_POST['pass1']));
            $p2 = trim(strip_tags($_POST['pass2']));

            if ($password != $p2) {
                $errors->add('expired_password', __('Passwords must match.'));
                return $errors;
            }

            //-- new password must not be the same as the current one
            if (wp_check_password($password, $user->data->user_pass, $user->ID)) {
                $errors->add('expired_password', __('The new password cannot be the same as the current one.'));
                return $errors;
            }
            //-- Enforce password policies
            if (!$this->IsUserExemptFromPolicies($user))
            {
                $this->CurrentPassIsOld = true;
                $this->CurrentUserLogin = $user->user_login;

                if ($password == $user->user_login) {
                    $errors->add('expired_password', __('<strong>ERROR</strong>: New password cannot be the same as the username.'));
                    return $errors;
                }
                if ($password == $user->user_email) {
                    $errors->add('expired_password', __('<strong>ERROR</strong>: New password cannot be the same as the email.'));
                    return $errors;
                }
                if (($c = $this->GetPasswordLen()) != 0) {
                    if (strlen($password) < $c) {
                        $errors->add('expired_password', sprintf(__('<strong>ERROR</strong>: New password must contain at least %d characters.'), $c));
                        return $errors;
                    }
                }
                if ($this->IsPolicyEnabled(self::POLICY_MIXCASE)) {
                    if (strtolower($password) == $password) {
                        $errors->add('expired_password', __('<strong>ERROR</strong>: New password must contain both uppercase and lowercase characters.'));
                        return $errors;
                    }
                }
                if ($this->IsPolicyEnabled(self::POLICY_NUMBERS)) {
                    if (!preg_match('/[0-9]/', $password)) {
                        $errors->add('expired_password', __('<strong>ERROR</strong>: New password must contain numbers.'));
                        return $errors;
                    }
                }
                if ($this->IsPolicyEnabled(self::POLICY_SPECIAL)) {
                    if (!preg_match('/[_\W]/', $password)) {
                        $errors->add('expired_password', __('<strong>ERROR</strong>: New password must contain special characters.'));
                        return $errors;
                    }
                }

                // update user passwords, if the policy applies
                $_nMaxSamePass = $this->GetMaxSamePass();
                if ($_nMaxSamePass) {
                    if ($this->_pwdHasBeenUsed($user->ID, $password)) {
                        $errors->add('expired_password',
                            sprintf(__('<strong>ERROR</strong>: New password must not be one of the previous %d used passwords.'), $_nMaxSamePass));
                        return $errors;
                    }
                    $this->_addPwdToList($user->ID, $password);
                }
                else {self::ClearUserPrevPwds($user->ID);}

                wp_set_password($password, $user->ID);
                $this->password_reset($user, $password);
                do_action('edit_user_profile_update', $user->ID);
            }
        }
        return $user;
    }

    // </editor-fold>


    // <editor-fold desc="Wordpress Extensions">
    /**
     * Get a global (across multiple sites) option.
     * @param string $name Option name.
     * @return mixed Option value or false if option not set.
     */
    protected function GetGlobalOption($name){
        $fn = $this->IsMultisite() ? 'get_site_option' : 'get_option';
        return $fn($name, false);
    }
    /**
     * Set a global (across multiple sites) option.
     * @param string $name Option name.
     * @param string $value Option value.
     */
    protected function SetGlobalOption($name, $value){
        $fn = $this->IsMultisite() ? 'update_site_option' : 'update_option';
        $fn($name, $value);
    }
    /**
     * Delete a global (across multiple sites) option.
     * @param string $name Option name.
     */
    protected function DeleteGlobalOption($name){
        $fn = $this->IsMultisite() ? 'delete_site_option' : 'delete_option';
        $fn($name);
    }

    /**
     * Get a user-specific option.
     * @param string $name Option name.
     * @param int $user_id (Optional) User id (default user if not set).
     * @return mixed Option value or false if option not set.
     */
    protected function GetUserOption($name, $user_id = null){
        if(is_null($user_id))$user_id = get_current_user_id();
        return get_user_option($name, $user_id);
    }
    /**
     * Set a user-specific option.
     * @param string $name Option name.
     * @param string $value Option value.
     * @param int $user_id (Optional) User id (default user if not set).
     */
    protected function SetUserOption($name, $value, $user_id = null){
        if(is_null($user_id))$user_id = get_current_user_id();
        update_user_option($user_id, $name, $value, true);
    }
    /**
     * @return string URL to plugin root with final slash.
     */
    public function GetBaseUrl(){
        return rtrim(plugins_url('', __FILE__), '/') . '/';
    }
    /**
     * @return string Get plugin path.
     */
    public function GetBaseDir(){
        return plugin_dir_path(__FILE__);
    }
    /**
     * @return string Get plugin name.
     */
    public function GetBaseName(){
        return plugin_basename(__FILE__);
    }
    /**
     * @return boolean Whether Wordpress is in multisite mode or not.
     */
    protected function IsMultisite(){
        return function_exists('is_multisite') && is_multisite();
    }
    /**
     * @return boolean Whether current user can manage plugin or not.
     */
    protected function IsManagingAdmin(){
        return current_user_can('manage_options');
    }
// </editor-fold>

    // <editor-fold desc="Misc Functionality">
    /**
     * @return string Password policy time to live as a string.
     */
    public function GetPasswordTtl(){
        $opt = $this->GetGlobalOption(self::OPT_NAME_TTL);
        return !$opt ? self::DEF_OPT_TTL : trim($opt);
    }
    /**
     * @return integer Password length policy (0=disabled).
     */
    public function GetPasswordLen(){
        $res = $this->GetGlobalOption(self::OPT_NAME_LEN);
        return $res === false ? self::DEF_OPT_LEN : (int)$res;
    }
    /**
     * Set new password time-to-live.
     * @param string $newTtl Password policy time to live as a string.
     * @throws Exception
     */
    public function SetPasswordTtl($newTtl){
        if(trim($newTtl)){
            $now = current_time('timestamp');
            $time = strtotime($newTtl, $now);
            if($time === false || $time < $now)
                throw new Exception(__('Password policy expiration time is not valid.'));
        }else $newTtl = '';
        $this->SetGlobalOption(self::OPT_NAME_TTL, $newTtl);
    }
    /**
     * @param integer $length Password length policy (0=disable policy).
     */
    public function SetPasswordLen($length){
        $this->SetGlobalOption(self::OPT_NAME_LEN, $length);
    }
    protected $_policy_flag_cache = null;
    /**
     * Returns password policy bitfield.
     * @return string Policy bitfield.
     */
    public function GetPolicyFlags(){
        if(is_null($this->_policy_flag_cache))
            $this->_policy_flag_cache = $this->GetGlobalOption(self::OPT_NAME_BIT);
        if($this->_policy_flag_cache === false)
            $this->_policy_flag_cache = '';
        return $this->_policy_flag_cache;
    }
    /**
     * @return array List of tokens (usernames or roles) exempt from password policies.
     */
    public function GetExemptTokens(){
        $res = $this->GetGlobalOption(self::OPT_NAME_XMT);
        return $res === false ? array() : (array)json_decode($res);
    }
    /**
     * Overwrite list of tokens (usernames or roles) exempt from password policies.
     * @param array $tokens New list of tokens.
     */
    public function SetExemptTokens($tokens){
        $this->SetGlobalOption(self::OPT_NAME_XMT, json_encode($tokens));
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
        $this->SetGlobalOption(self::OPT_NAME_BIT, $flags);
        $this->_policy_flag_cache = null; // clear cache
    }
    /**
     * @return integer Maximum number of same passwords allowed.
     */
    public function GetMaxSamePass(){
        return (int)$this->GetGlobalOption(self::OPT_NAME_MSP);
    }
    /**
     * @param integer $value New maximum number of same passwords allowed.
     */
    public function SetMaxSamePass($value){
        $this->SetGlobalOption(self::OPT_NAME_MSP, $value);
    }
    protected function EchoIdent($name){
        echo self::DEF_PFX . '_' . $name;
    }
    protected function IsPostIdent($name){
        return isset($_POST[self::DEF_PFX . '_' . $name]);
    }
    protected function IsJustInstalled(){
        return ($this->GetGlobalOption(self::OPT_NAME_TTL) === false)
        || ($this->GetGlobalOption(self::OPT_NAME_LEN) === false);
    }
    protected function GetPostIdent($name){
        return $_POST[self::DEF_PFX . '_' . $name];
    }
    protected function UpdateWpOptions(){
        if($this->IsPostIdent('ttl'))
            $this->SetPasswordTtl($this->GetPostIdent('ttl'));
        if($this->IsPostIdent('len'))
            $this->SetPasswordLen($this->GetPostIdent('len'));
        $this->SetPolicyState(self::POLICY_MIXCASE, $this->IsPostIdent('cpt'));
        $this->SetPolicyState(self::POLICY_NUMBERS, $this->IsPostIdent('num'));
        $this->SetPolicyState(self::POLICY_SPECIAL, $this->IsPostIdent('spc'));
        $this->SetExemptTokens(isset($_REQUEST['ExemptTokens']) ? $_REQUEST['ExemptTokens'] : array());
        if($this->IsPostIdent('msp'))
            $this->SetMaxSamePass((int)$this->GetPostIdent('msp'));
    }

    protected function ResetWpPasswords()
    {
        $users = new WP_User_Query(array('blog_id' => 0));
        foreach ($users->get_results() as $user) {
            $new_password = wp_generate_password();
            wp_set_password($new_password, $user->ID);
            // The blogname option is escaped with esc_html on the way into the database in sanitize_option
            // we want to reverse this for the plain text arena of emails.
            $blogname = wp_specialchars_decode(get_option('blogname'), ENT_QUOTES);

            $message = '<!DOCTYPE html><html><head><meta charset="UTF-8"/></head><body>';
            $message .= sprintf(__('<p>Your password for <strong>%s</strong> has been reset.</p>'), $blogname) . "\r\n\r\n";
            $message .= sprintf(__('<p>New Password: <strong>%s</strong></p>'), $new_password) . "\r\n\r\n";
            $message .= sprintf(__('<p>Please log in and change your password:')) . "\r\n";
            $message .= wp_login_url() . "</p>\r\n";
            $message .= '</body></html>';
            $result = self::SendNotificationEmail($user->user_email, $message);
            if ($result) {
                // reset & expire
                $this->SetGlobalOption(self::OPT_USER_RST_PWD . '_' . $user->ID, true);
                update_user_option($user->ID, self::OPT_NAME_UPM, current_time('timestamp'));
            }
        }
    }
    protected function SendNotificationEmail($emailAddress, $message){
        $headers = sprintf('From: %s <%s>', get_bloginfo('name'), get_bloginfo('admin_email'))."\r\n";
        $headers .= sprintf('Reply-to: %s <%s>', get_bloginfo('name'), get_bloginfo('admin_email'))."\r\n";
        $headers .= "MIME-Version: 1.0\r\n";
        $subject = 'Password has been reset';
        //@see: http://codex.wordpress.org/Function_Reference/wp_mail
        add_filter('wp_mail_content_type', array($this, '_set_html_content_type'));
        $result = wp_mail($emailAddress, $subject, $message, $headers);
        // Reset content-type to avoid conflicts -- http://core.trac.wordpress.org/ticket/23578
        remove_filter('wp_mail_content_type', array($this, '_set_html_content_type'));
        return $result;
    }
    final public function _set_html_content_type(){ return 'text/html'; }
    protected function GetTokenType($token){
        $users = array();
        foreach(get_users('blog_id=0&fields[]=user_login') as $obj)
            $users[] = $obj->user_login;
        $roles = array_keys(get_editable_roles());
        if(in_array($token, $users))return 'user';
        if(in_array($token, $roles))return 'role';
        return 'other';
    }
    /**
     * Renders WordPress settings page.
     */
    public function ManageWpOptions(){
        // control access to plugin
        if (!$this->IsManagingAdmin()) {
            wp_die(__('You do not have sufficient permissions to access this page.'));
        }
        // update submitted settings
        if(isset($_POST) && count($_POST)){
            try {
                switch(true){
                    case isset($_POST[self::DEF_PFX.'_snt']):
                        $this->UpdateWpOptions();
                        ?><div class="updated"><p><strong><?php _e('Settings saved.'); ?></strong></p></div><?php
                        break;
                    case isset($_POST[self::DEF_PFX.'_rst']):
                        $this->ResetWpPasswords();
                        ?><div class="updated"><p><strong><?php _e('All passwords have been reset.'); ?></strong></p></div><?php
                        break;
                    default:
                        throw new Exception('Unexpected form submission content.');
                }
            } catch (Exception $ex) {
                ?><div class="error"><p><strong><?php _e(__('Error').': '.$ex->getMessage()); ?></strong></p></div><?php
            }
        }
        // display settings page
        ?><div class="wrap">
        <h2><?php echo __('WordPress Password Policy Manager Settings'); ?></h2>
        <form method="post" id="wppm_settings">
            <input type="hidden" name="page" value="<?php echo esc_attr($_REQUEST['page']); ?>" />
            <input type="hidden" id="ajaxurl" value="<?php echo esc_attr(admin_url('admin-ajax.php')); ?>" />
            <div id="wppm-adverts">
                <a href="http://www.wpwhitesecurity.com/plugins-premium-extensions/email-notifications-wordpress/?utm_source=wppmplugin&utm_medium=settingspage&utm_campaign=notifications" target="_blank">
                    <img src="<?php echo $this->GetBaseUrl();?>/img/notifications_250x150.gif" width="250" height="150" alt="">
                </a>
                <a href="http://www.wpwhitesecurity.com/plugins-premium-extensions/search-filtering-extension/?utm_source=wppmplugin&utm_medium=settingspage&utm_campaign=search" target="_blank">
                    <img src="<?php echo $this->GetBaseUrl();?>/img/search_250x150.gif" width="250" height="150" alt="">
                </a>
                <a href="http://www.wpwhitesecurity.com/plugins-premium-extensions/wordpress-reports-extension/?utm_source=wppmplugin&utm_medium=settingspage&utm_campaign=reports" target="_blank">
                    <img src="<?php echo $this->GetBaseUrl();?>/img/reporting_250x150.gif" width="250" height="150" alt="">
                </a>
            </div>
            <table class="form-table">
                <tbody>
                <tr valign="top">
                    <th scope="row"><label for="<?php $this->EchoIdent('ttl'); ?>"><?php _e('Password Expiration Policy'); ?></label></th>
                    <td>
                        <input type="text" id="<?php $this->EchoIdent('ttl'); ?>" name="<?php $this->EchoIdent('ttl'); ?>"
                               value="<?php echo esc_attr($this->GetPasswordTtl()); ?>" size="20" class="regular-text ltr">
                        <p class="description"><?php _e('Examples: <code>5 days</code> <code>20 days 6 hours</code> <code>3 weeks</code>'); ?></p>
                        <?php _e('Leave blank to disable Password Expiry policy.'); ?>
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
                            ?></select> <?php _e('characters'); ?><br/>
                        <?php _e('Leave blank to disable Password Length policy.'); ?>
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
                                <?php _e('Password must contain a mix of uppercase and lowercase characters.'); ?>
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
                                <?php _e('Password must contain numeric digits (<code>0-9</code>).'); ?>
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
                                <?php _e('Password must contain special characters (eg: <code>.,!#$_+</code>).'); ?>
                            </label>
                        </fieldset>
                    </td>
                </tr>
                <tr valign="top">
                    <th><label for="<?php $this->EchoIdent('msp'); ?>"><?php _e('Password History Policy'); ?></label></th>
                    <td>
                        <fieldset>
                            <?php _e('Remember'); ?>
                            <select type="text" id="<?php $this->EchoIdent('msp'); ?>" name="<?php $this->EchoIdent('msp'); ?>"><?php
                                $curr = $this->GetMaxSamePass();
                                foreach(array_merge(array(0), range(2, 10)) as $value){
                                    $sel = ($value == $curr) ? ' selected="selected"' : '';
                                    ?><option value="<?php echo $value; ?>"<?php echo $sel; ?>>
                                    <?php echo ($value == 0 ? '' : $value); ?>
                                    </option><?php
                                }
                                ?></select> <?php _e('old passwords'); ?><br/>
                            <?php _e('Leave blank to disable password history policy.'); ?>
                        </fieldset>
                    </td>
                </tr>
                <tr>
                    <th><label for="ExemptTokenQueryBox"><?php _e('Users and Roles Exempt From Policies'); ?></label></th>
                    <td>
                        <fieldset>
                            <input type="text" id="ExemptTokenQueryBox" style="float: left; display: block; width: 250px;">
                            <input type="button" id="ExemptTokenQueryAdd" style="float: left; display: block;" class="button-primary" value="Add">
                            <br style="clear: both;"/>
                            <p class="description"><?php
                                _e('Users and Roles in this list are free of all Password Policies.');
                                ?></p>
                            <div id="ExemptTokenList"><?php
                                foreach($this->GetExemptTokens() as $item){
                                    ?><span class="sectoken-<?php echo $this->GetTokenType($item); ?>">
                                    <input type="hidden" name="ExemptTokens[]" value="<?php echo esc_attr($item); ?>"/>
                                    <?php echo esc_html($item); ?>
                                    <a href="javascript:;" title="Remove">&times;</a>
                                    </span><?php
                                }
                                ?></div>
                        </fieldset>
                    </td>
                </tr>
                <tr valign="top">
                    <th scope="row"><label for="rst-submit-button"><?php _e("Reset All Users' Passwords");?></label></th>
                    <td><input id="rst-submit-button" type="submit" name="<?php $this->EchoIdent('rst'); ?>" class="button-secondary" value="<?php esc_attr_e(__('Reset All Passwords')); ?>"
                               onclick="return confirm(<?php esc_attr_e(json_encode(__('Are you sure you want to reset all passwords?'))); ?>);"/></td>
                </tr>

                </tbody>
            </table>
            <!-- Policy Flags: <?php echo $this->_policy_flag_cache; ?> -->
            <p class="submit">
                <input type="submit" name="<?php $this->EchoIdent('snt'); ?>" class="button-primary" value="<?php esc_attr_e(__('Save Changes')); ?>" />
            </p>
        </form>
        </div><?php
    }
    /**
     * Returns whether policies for specified user are applicable or not.
     * @param WP_User|integer $userOrUid Either user instance or user id.
     * @return boolean True if the policies are disabled, false otherwise.
     */
    public function IsUserExemptFromPolicies($userOrUid){
        $user = is_int($userOrUid) ? get_userdata($userOrUid) : $userOrUid;
        $tokens = $this->GetExemptTokens();
        foreach(array_merge($user->roles, array($user->user_login)) as $token)
            if(in_array($token, $tokens))
                return true;
        return false;
    }
    /**
     * Returns whether the password is too old or not.
     * @param integer $setTime The timestamp of when the password was set.
     * @return boolean True if old, false otherwise.
     */
    public function IsPasswordOld($setTime){
        $ttl = $this->GetPasswordTtl();
        if(!trim($ttl))return false;
        return strtotime($ttl, $setTime) <= current_time('timestamp');
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
        $time = (int)$this->GetUserOption(self::OPT_NAME_UPM, $user_ID);
        if(!$time)$time = strtotime(get_userdata($user_ID)->user_registered);
        return $time;
    }
    protected function GetOldPass($user_id = null){
        $l = $this->GetUserOption(self::OPT_NAME_OPL, $user_id);
        return $l === false ? array() : json_decode($l);
    }
    protected function AddNewPass($pass, $user_id = null){
        $pass = md5($pass); // security feature
        $l = $this->GetOldPass();
        $l[] = $pass;
        $l = array_slice(array_unique($l), - $this->GetMaxSamePass());
        $this->SetUserOption(self::OPT_NAME_OPL, json_encode($l), $user_id);
    }
    protected function IsNewPass($pass, $user_id = null){
        $pass = md5($pass); // security feature
        $l = $this->GetUserOption(self::OPT_NAME_OPL, $user_id);
        $l = $l === false ? array() : json_decode($l);
        return !in_array($pass, $l);
    }
    private static function _getPwdListOptName($uid){
        return $uid.'_'.self::OPT_USER_PWDS;
    }
    private function _pwdHasBeenUsed($uid, $pwd){
        $name = self::_getPwdListOptName($uid);
        $list = $this->GetGlobalOption($name);
        if(! $list){
            return false;
        }
        return in_array(md5($pwd), $list);
    }
    private function _addPwdToList($uid, $pwd){
        $name = self::_getPwdListOptName($uid);
        $list = $this->GetGlobalOption($name);
        $md5p = md5($pwd);
        if(! $list){
            $list = array($md5p);
        }
        else {
            $count = count($list);
            if ($count == $this->GetMaxSamePass()) {
                array_shift($list);
            }
            array_push($list, $md5p);
        }
        $this->SetGlobalOption($name,$list);
        return true;
    }

    /**
     * Static version of the DeleteGlobalOption method
     * @internal
     * @param $name
     */
    public static function _DeleteGlobalOption($name){
        $fn = (function_exists('is_multisite') && is_multisite()) ? 'delete_site_option' : 'delete_option';
        return $fn($name);
    }

    public static function ClearUserPrevPwds($uid){
        return self::_DeleteGlobalOption(self::_getPwdListOptName($uid));
    }
    // </editor-fold>

    // <editor-fold desc="WordPress Hooks and Filters">

    public function profile_update($user_id){
        $this->_addPwdToList($user_id, get_userdata($user_id)->user_pass);
    }
    public function user_profile_update_errors($errors, $update, $user){
        if (!$errors->get_error_data('pass') && !$errors->get_error_data('expired_password'))
            update_user_option($user->ID, self::OPT_NAME_UPM, current_time('timestamp'));
    }
    public function user_register($user_id){
        $this->_addPwdToList($user_id, get_userdata($user_id)->user_pass);
    }
    public function password_reset($user/*, $new_pass*/){
        update_user_option($user->ID, self::OPT_NAME_UPM, current_time('timestamp'));
    }

    public function plugin_action_links($old_links){
        $new_links = array(
            '<a href="' . admin_url('options-general.php?page=password_policy_settings') . '">' .
            __('Configure Password Policies') .
            '</a>',
        );
        return array_merge($new_links, $old_links);
    }
    public function admin_menu(){
        add_options_page(__('Password Policies'), __('Password Policies'), 'manage_options', self::PLG_CONFIG_MENU_NAME, array($this, 'ManageWpOptions'));
    }
    public function network_admin_menu(){
        add_options_page(__('Password Policies'), __('Password Policies'), 'manage_network', self::PLG_CONFIG_MENU_NAME, array($this, 'ManageWpOptions'));
        add_submenu_page('settings.php', __('Password Policies'), __('Password Policies'), 'manage_network_options', self::PLG_CONFIG_MENU_NAME, array($this, 'ManageWpOptions'));
    }
    public function admin_enqueue_scripts(){
        wp_enqueue_style('wppm', $this->GetBaseUrl() . 'css/wppm.css', array(), filemtime($this->GetBaseDir() . 'css/wppm.css'));
    }
    public function admin_footer(){
        if($this->IsJustInstalled()){
            wp_enqueue_style('wp-pointer');
            wp_enqueue_script('wp-pointer');
        }
        wp_enqueue_script('wppm', $this->GetBaseUrl() . 'js/wppm.js', array(), filemtime($this->GetBaseDir() . 'js/wppm.js'));
    }
    public function admin_print_footer_scripts(){
        $isOnPluginPage = isset($_REQUEST['page']) && $_REQUEST['page']==self::PLG_CONFIG_MENU_NAME;
        if($this->IsJustInstalled() && $this->IsManagingAdmin() && !$isOnPluginPage){
            $tle = __('Configure Password Policies');
            $txt = __('You have just installed WP Password Policy manager. All password policies are disabled by default. Click the button below to configure the WordPress password policies.');
            $btn = __('Configure Policies');
            $url = admin_url('options-general.php?page='.self::PLG_CONFIG_MENU_NAME);
            ?><script type="text/javascript">
                jQuery(function($) {
                    $('#wp-admin-bar-my-account').pointer({
                        buttons: function () {
                            return $(<?php echo json_encode('<a class="button-primary" href="'.$url.'">'.$btn.'</a>'); ?>);
                        },
                        'content': <?php echo json_encode("<h3>$tle</h3><p>$txt</p>"); ?>
                    }).pointer('open');
                });
            </script><?php
        }
    }
    public function wp_ajax_check_security_token(){
        if(!$this->IsManagingAdmin())
            die('Access Denied.');
        if(!isset($_REQUEST['token']))
            die('Token parameter expected.');
        die($this->GetTokenType($_REQUEST['token']));
    }
    public static function on_uninstall(){
        if ( ! current_user_can('activate_plugins'))
            return;
        $users = get_users(array('fields' => array('ID')));
        foreach ($users as $user)
            self::ClearUserPrevPwds($user->ID);
    }
    // </editor-fold>
}
register_uninstall_hook(__FILE__, array('WpPasswordPolicyManager', 'on_uninstall'));
// Create & Run the plugin
return WpPasswordPolicyManager::GetInstance();