=== WP Password Policy Manager ===
Contributors: WPWhiteSecurity
License: GPLv3
License URI: http://www.gnu.org/licenses/gpl.html
Tags: wordpress password policy, password policy, password policy manager, wordpress password, password strength, password, authentication, security, wordpress user password, strong wordpress password
Requires at least: 3.0.1
Tested up to: 4.0
Stable tag: 0.2

Configure strong WordPress password policies for users to improve the security of your WordPress by ensuring users are not using weak passwords.

== Description ==

= Ensure WordPress Users Use Strong Passwords =
Thousands of WordPress blogs and websites get hacked each year because users use weak passwords. Do not let your WordPress become a statistic; ensure that all your WordPress users use strong passwords and change them frequently with WP Password Policy Manager plugin.

= Why WP Password Policy Manager? =
With WP Password policy manager you can easily configure WordPress password policies to enforce users to use strong passwords.

Your WordPress users do not have to get used to new systems or procedures; WP Password Policy Manager integrates seamlessly within your WordPress login page and uses the standard WordPress UI as can be seen from these [screenshots](http://wordpress.org/plugins/wp-password-policy-manager/screenshots/). 

= Configurable WordPress Password Policies =
WordPress Administrators can configure any of the below policies to ensure their users are using strong WordPress passwords:

* Password Age
* Minimum Password Length
* Mixed Case Policy (enforce users to use both uppercase and lowercase characters in passwords)
* Numeric Digits Policy (enforce users to use numbers in their passwords)
* Special Characters Policy (enforce users to use special characters in their passwords) 

= Built-in WordPress Password Policies =
Once a WordPress user's password expires, the new password:

* Cannot be the same as the username
* Cannot be the same as the previous one

= Changing the WordPress Password =
Once a WordPress user's password is expired, he or she is notified upon trying to login. To assist the user in choosing a strong password, the policies are also listed in the login page as can be seen in the [screenshots](http://wordpress.org/plugins/wp-password-policy-manager/screenshots/).

= Plugin Newsletter =
To keep yourself updated with what is new and updated in our WordPress security plugins please subscribe to the [WP White Security Plugins Newsletter](http://eepurl.com/Jn9sP).

= Other Links =

* [WP Password Policy Manager Official Page](http://www.wpwhitesecurity.com/wordpress-security-plugins/wp-password-policy-manager/)

== Installation ==

1. Upload the `wp-password-policy-manager` folder to the `/wp-content/plugins/` directory
2. Activate the WP Password Policy Manager plugin from the 'Plugins' menu in the WordPress Administration Screens
3. Configure the Password Age from the Password Policy entry in the Settings menu

== Frequently Asked Questions ==

= How will a user know that his or her password is expired? =
If a WordPress user's password is expired, the user will be notified and asked to change the password upon trying to login to WordPress.

= How can I disable a WordPress password policy? =
If you do not specify a value for a specific policy it is automatically disabled. Alternatively untick the check box next to the policy from the Password Policies nodes in the WordPress Settings.

== Screenshots ==

1. Expired password login page allows users to specify a new password and instructs them of which policies are enabled
2. Administrators can configure password policies from the Password Policies node in WordPress settings 

== Changelog ==

= 0.2 (2014-02-25) =
* New Password Policies
  * Password length policy - specify the minimum length a password should be
  * Mixed case policy - if enabled, users should use both uppercase and lowercase characters in passwords
  * Numeric Digits policy - if enabled, users should use numeric digits in their passwords
  * Special Character policy - if enabled, users should use special characters in their passwords

* New Plugin Features
  * Added list of enabled policies in password reset screen to help users generate a strong password
  * Added a notification box which pops up on installation to help administrators configure the password policies             

= 0.1 (2014-01-15) =
* Initial release
