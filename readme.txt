=== WP Block ===
Contributors: wpblock
Donate link: https://evsec.com/donate
Tags: hackers, security, wpscan, firewall
Requires at least: 3.0.1
Tested up to: 4.7.3
Stable tag: 4.7.3
License: GPLv2 or later
License URI: http://www.gnu.org/licenses/gpl-2.0.html

Prevent hackers using WPScan to find vulnerabilities in your site, disable this plugin when you are security testing or looking for vulnerabilities

== Description ==

We love security testing, we do it! We love WPSCAN, we use it! However we don't love people abusing WPSCAN and other automated methods to try and gain access to WordPress sites through known and often easy vulnerabilities. WP Block is not a silver bullet, but it will stop unskilled attackers, bots and automated attacks which account for over 90% of all WordPress breaches. The other 10% can be offset with a good firewall, IDS and NSM services. Server load will also be lower and sites faster as this tool will prevent a lot of WordPress related automated testing.

[!] You can prevent most of the common attacks simply by keeping plugins, themes and the core WordPress framework updated

Benefits
*   Disables access to admin for everyone except admins and editors
*   Disables the use of WPScan, a tool commonly used by hackers to attack WordPress, also blocks other automated WP scanners
*   Blocks hackers from scanning your website for admin users, vulnerable themes, vulnerable plugins and exposed files
*   Reduces the load on your server
*   Prevents access to sensitive files

== Installation ==

1. Upload `plugin-name.php` to the `/wp-content/plugins/` directory or install from the plugins menu in WordPress
2. Activate the plugin through the 'Plugins' menu in WordPress

== Frequently Asked Questions ==

= What is WPSCAN? =

WPScan is a WordPress vulnerability scanner.

= What is a vulnerability? =

In computer security, a vulnerability is a weakness which allows an attacker to reduce a system's information assurance. Vulnerability is the intersection of three elements: a system susceptibility or flaw, attacker access to the flaw, and attacker capability to exploit the flaw.

== Screenshots ==

1. This screen shot description corresponds to screenshot-1.(png|jpg|jpeg|gif). Note that the screenshot is taken from
the /assets directory or the directory that contains the stable readme.txt (tags or trunk). Screenshots in the /assets
directory take precedence. For example, `/assets/screenshot-1.png` would win over `/tags/4.3/screenshot-1.png`
(or jpg, jpeg, gif).
2. This is the second screen shot

== Changelog ==

= 1.0 =
* First release

= 1.2 =
* Fully tested and stable release

= 1.3 =
* Fixed a bug which caused error on dashboard when conflicting plugins were installed

= 1.4 =
* Added more htaccess security headers
* Added more bots, scanners and payloads to block

== Upgrade Notice ==


== About Evsec ==

We help companies optimise and secure infrastructure, reduce operational costs and minimise exposure to risks.

We mitigate security and legal risks through real-time monitoring, offensive testing, administration and compliance assessments and we optimise infrastructure and reduce operational costs by streamlining IT infrastructure, on premise or in the cloud and implementing operational IT best practises.

And when things do inevitably go wrong, our customers can always rely on our dedicated security and operational support specialists to be on hand
24 hours a day, 7 days a week, 365 days a year.
