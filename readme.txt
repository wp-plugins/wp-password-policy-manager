=== WP Password Policy Manager ===
Contributors: WPWhiteSecurity
Donate link: https://www.paypal.com/cgi-bin/webscr?cmd=_donations&business=abela%2erobert%40gmail%2ecom
License: GPLv3
License URI: http://www.gnu.org/licenses/gpl.html
Tags: wordpress password policy, password policy, password policy manager, wordpress password, password strength, password, authentication, security, wordpress user password, strong password, strong wordpress password, authentication, password security, password expire, strong wordpress password plugin
Requires at least: 3.6.0
Tested up to: 4.0.1
Stable tag: 0.4

Configure WordPress password policies to ensure all WordPress users use strong passwords and improve the security of your WordPress.

== Description ==

= Ensure WordPress Users Use Strong Passwords =
Thousands of WordPress blogs and websites get hacked each year because of weak passwords. One way to [protect your WordPress from automated brute force attacks](http://www.wpwhitesecurity.com/wordpress-security/protect-wordpress-brute-force-attacks/) is to use strong passwords. Do not let your WordPress become a statistic. Ensure that all your WordPress users use strong passwords and change them frequently with WP Password Policy Manager plugin.

= Why WP Password Policy Manager? =
You can easily configure strong WordPress password policies within a few seconds and your WordPress users do not have to get used to new systems and interfaces. WP Password Policy Manager integrates seamlessly within your WordPress login page and uses the standard WordPress UI as can be seen from these [screenshots](http://wordpress.org/plugins/wp-password-policy-manager/screenshots/), hence the process is transparent to your users.

= Configurable WordPress Password Policies =
As a WordPress administrators you can configure any of the below password policies to ensure all your WordPress users use strong password:

> <strong>Password Expire Time</strong><br>
> This policy allows you to specify for how long a password is valid before it expires. For example if you specify 1 month, after 1 month the WordPress user will be forced to change his existing password prior to logging in.
>
> <strong>Password Length</strong><br>
> This policy allows you to specify the minimum number of characters a password should consist of.
>
> <strong>Mixed Case Policy</strong><br>
> When you enable this policy all of the WordPress users' passwords should contain both lower and UPPER case characters.
>
> <strong>Numeric Digits Policy</strong><br>
> When you enable this policy all of the WordPress users' passwords should contain numeric digits.
>
> <strong>Special Characters Policy</strong><br>
> When you enable this policy all of the WordPress users' passwords should contain special characters, such as <strong>! ? * &</strong> etc.
>
> <strong>Password History Policy</strong><br>
> This policy allows you to specify how many passwords should the plugin remember so WordPress users do not use the same password. For example if you specify 8 the user can reuse an old password on the ninth time his password is changed.
>
> <strong>Note:<strong>WP Password Policy Manager stored users' passwords the same way WordPress stores them, hence it is secure.

= Reset All WordPress Users Password with One Click =
In case your WordPress has been hacked or need to reset all WordPress users' password you can do so with a single click from the passwords policies configuration. Once you reset all of the WordPress users' passwords each user will receive an email with a new random generated password. Since the password is sent over email once the WordPress users log in they will be asked to change the password again to ensure maximum security.

= Keep Track of All WordPress Users Activity on WordPress =
Another way to ensure WordPress security is to have full control of your WordPress by keeping an audit log of all changes that happen on your [WordPress with WP Security Audit Log](https://wordpress.org/plugins/wp-security-audit-log/) plugin.

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

== Screenshots ==

1. Expired password login page allows the user to specify a new password
2. Administrators can configure password policies from the Password Policies node in WordPress settings
3. WordPress password policies are also applied in the WordPress user profile page ensuring users always use strong passwords
4. WordPress password policies are also applied in the lost / reset password page in WordPress ensuring strong password policies are never bypassed

== Changelog ==


= 0.4 (2014-12-1) =
* **Bug Fix**
	* Fixed an issue where the password was not being reset properly when changed by the admin on a user's profile page


= 0.3 (2014-11-24) =
* **New Plugin Features**
	* Password policies now also enforced in WordPress user profile page therefore when a user changes his own or someone's else password from the profile page he should adhere to the policies
	* Password policies now also enforced in "WordPress Lost Password" page, therefore when a user uses the "Lost Password" link in the login the new password should adhere to the policies
	* Added Reset All Passwords functionality - administrators can reset the passwords of all users with just 1 click (email is sent to all users with new password and once they login they should change their password again)
	* Excempt users and roles from policies - administrators can excempt users and roles from the password policies
	* Added link to Password Policies in the WordPress plugins page

* **New Password Policy**
	* Password history - if enabled the plugin will remember a configurable number of previous passwords the WordPress user already used to avoid using the same password

* **Bug Fix**
	* Fixed an issue related to timezones [support ticket](https://wordpress.org/support/topic/date_default_timezone_set-timezone-id-is-invalid-1)

= 0.2 (2014-02-25) =
* **New Password Policies**
	* Password length policy - specify the minimum length a user's password should be
	* Mixed case policy - if enabled users should use both lower and UPPERcase characters in their passwords
	* Numeric digits policy - if enabled users should use numeric digits in their passwords
	* Special characters policy - ie enabled users should use special characters in their passwords

* **New Plugin Features**
	* Added list of enabled policies in password reset page for users to follow when writing a new password
	* Added a popup notification box so after install administrators can immediately configure the password policies

= 0.1 (2014-01-15) =
* **Initial release**
