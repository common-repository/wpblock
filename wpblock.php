<?php
/*
Plugin Name: wpblock
Description: Prevent WPScans on your site, disable this plugin when you are security testing or looking for vulnerabilities!
Version: 1.4.0
Author: Evsec
Author URI: https://evsec.com

wpblock - Prevent WPScans on your site, disable this plugin when you are security testing or looking for vulnerabilities!
Copyright (C) 2017  Evsec Ltd

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

// Block Direct Access
defined( 'ABSPATH' ) or die();

// Initialise Scan Count
add_option("ev_wpblk_total_scans", 0);

// Register a Scan to the Database
function ev_wpblk_registerScanToDb(){
	$scan_count = get_option("ev_wpblk_total_scans");
	$new_count = intval($scan_count)+1;
	update_option("ev_wpblk_total_scans", $new_count);
}

// Create Admin Notice
function ev_wpblk_admin_scan_notice() {
	$scan_count = intval(get_option("ev_wpblk_total_scans"));
	if ($scan_count === 0) {
		$wpblock_status = "Good news, no direct WordPress application scans yet, we will keep watching.";
	} elseif ($scan_count === 1) {
		$wpblock_status = "WP Block prevented " . $scan_count . " scan on your website.";
	} else {
		$wpblock_status = "WP Block prevented " . $scan_count . " scans on your website.";
	}

    ?>
		<img src="<?php echo plugin_dir_url( __FILE__ ); ?>logo.jpg" style="width: 200px;" /><br />
		<p><strong><?php echo $wpblock_status; ?></strong></p><br>
		<img src="<?php echo plugin_dir_url( __FILE__ ); ?>evsec.png" style="width: 80px;" /><br />
		<small>Are you ready for the GDPR? Visit <a href='https://evsec.com/gdpr'>https://evsec.com/gdpr</a> for more info</small>
    <?php
}

add_action( 'wp_dashboard_setup', 'ev_wpblk_wpblock_widget' );
function ev_wpblk_wpblock_widget() {
	wp_add_dashboard_widget(
		'wpblock',
    	'WP Block',
		'ev_wpblk_admin_scan_notice'
  	);

	if (isset($wp_meta_boxes)) {
		// Then we make a backup of your widget.
		$wpblockwidget = $wp_meta_boxes['dashboard']['normal']['core']['wpblock'];
		// We then unset that part of the array.
		unset($wp_meta_boxes['dashboard']['normal']['core']['wpblock']);
		// Now we just add your widget back in.
		$wp_meta_boxes['dashboard']['side']['core']['wpblock'] = $wpblockwidget;
	}
}


// Add notice to admin notices
//add_action( 'admin_notices', 'ev_wpblk_admin_scan_notice' );

// Check to see if '?advanced_fingerprinting=' is set
if (isset($_GET['advanced_fingerprinting'])) {
	status_header(404);
	ev_wpblk_registerScanToDb();
	die();
}

// Check to see if '?plugin_enumeration=' is set
if (isset($_GET['plugin_enumeration'])) {
	// Display something random
	ev_wpblk_registerScanToDb();
	die('<!-- ' .uniqid() .'-->');
}

//if (!is_admin() && isset($_REQUEST['author'])) {
	//ev_wpblk_registerScanToDb();
	//status_header(404);
	//die();
//}

add_action('init', 'ev_wpblk_wpblock_init');
function ev_wpblk_wpblock_init() {

	global $wp_version;
	$transient_name = 'wpblock_'.$_SERVER['REMOTE_ADDR'];
	$transient_value = get_transient($transient_name);
	if ($transient_value !== false) {
		die();
	}

	// Check to see if '?wp_config_enumeration=' is set
	if (isset($_GET['wp_config_enumeration'])) {
		set_transient($transient_name, 1, DAY_IN_SECONDS);
		ev_wpblk_registerScanToDb();
		die();
	}

	// Check to see if  @user_agent = "WPScan v#{WPSCAN_VERSION} (http://wpscan.org)"
	if (!empty($_SERVER['HTTP_USER_AGENT']) && preg_match('/WPScan/i', $_SERVER['HTTP_USER_AGENT'])) {
		ev_wpblk_registerScanToDb();
	 	die();
	}

	// WordPress version identified from stylesheets numbers
	$wp_version = '0001';
}

// Block access to robots.txt
add_action('do_robots', 'ev_wpblk_wpblock_do_robots', 1);
function ev_wpblk_wpblock_do_robots() {
	ev_wpblk_registerScanToDb();
	status_header(404);
	die();
}

//function ev_wpblk_add_fake_xmlrpc() {
	// We don't want to display die('XML-RPC server accepts POST requests only.'); on $_GET
	//if (!empty($_POST)) {
		//return 'wp_xmlrpc_server';
	//} else {
		//return 'fake_xmlrpc';
	//}
//}

add_filter('wp_xmlrpc_server_class', 'ev_wpblk_wpblock_fake_xmlrpc');
class ev_wpblk_wpblock_fake_xmlrpc {
	function serve_request() {
		ev_wpblk_registerScanToDb();
		die();
	}
}

// Remove <meta name="generator" content="WordPress" />
remove_action('wp_head', 'wp_generator');
add_filter('the_generator', 'ev_wpblk_wpblock_remove_generator');
function ev_wpblk_wpblock_remove_generator() {
    return '';
}

register_activation_hook( __FILE__, 'ev_wpblk_wpblock_activation');
function ev_wpblk_wpblock_activation() {
	add_filter('rewrite_rules', 'wpblock_rewrite_rules_filter');
	function wpblock_rewrite_rules_filter($rules){
			$exploded = explode("\n", $rules);
			$my_rules = array(
				// SECURITY HEADERS
				'Header add X-Frame-Options "SAMEORIGIN"',
				'Header add X-XSS-Protection "1; mode=block"',
				'Header add X-Content-Security-Policy "default-src \'self\'"',
				'Header add X-Content-Type-Options "nosniff"',
				'Header unset Etag',
				'Header unset Server',
				'ServerSignature Off',
				'Header unset X-Pingback',
				// CORE WP BLOCK RULES
				'RewriteRule ^readme\.html$ - [R=404,L,NC]', // Disable access to readme.html
				'RewriteRule ^readme\.txt$ - [R=404,L,NC]', // Disable access to readme.txt
				'RewriteRule ^changelog\.txt$ - [R=404,L,NC]', // Disable access to changelog.txt
				'RewriteRule ^wp-includes/rss-functions\.php$ - [R=404,L,NC]', // Disable Full Path Disclosure
				'RewriteRule ^wp-includes/js/tinymce/wp-tinymce\.js\.gz$ index.php?advanced_fingerprinting=1 [L]', // prevent advanced fingerprinting
				'RewriteRule ^(.*)wp-content/plugins/(.*)/readme\.txt$ - [R=404,L]', // Not display plugins readmes
				'RewriteCond %{REQUEST_FILENAME} !-f',
				'RewriteRule ^(.*)wp-content/plugins/(.*)$ index.php?plugin_enumeration=1 [L]', // Always display something when visit plugin dir
				'RewriteRule ^wp-config\.php\.save$ index.php?wp_config_enumeration=1 [L]', // wp-config enumeration
				'RewriteRule ^\.wp-config\.php\.swp$ index.php?wp_config_enumeration=1 [L]',
				'RewriteRule ^wp-config\.php\.swp$ index.php?wp_config_enumeration=1 [L]',
				// BAD BOTS
                'RewriteCond %{HTTP_USER_AGENT} ^BlackWidow [OR]',
                'RewriteCond %{HTTP_USER_AGENT} ^Bot\ mailto:craftbot@yahoo.com [OR]',
                'RewriteCond %{HTTP_USER_AGENT} ^ChinaClaw [OR]',
                'RewriteCond %{HTTP_USER_AGENT} ^Custo [OR]',
                'RewriteCond %{HTTP_USER_AGENT} ^DISCo [OR]',
                'RewriteCond %{HTTP_USER_AGENT} ^Download\ Demon [OR]',
                'RewriteCond %{HTTP_USER_AGENT} ^eCatch [OR]',
                'RewriteCond %{HTTP_USER_AGENT} ^EirGrabber [OR]',
                'RewriteCond %{HTTP_USER_AGENT} ^EmailSiphon [OR]',
                'RewriteCond %{HTTP_USER_AGENT} ^EmailWolf [OR]',
                'RewriteCond %{HTTP_USER_AGENT} ^Express\ WebPictures [OR]',
                'RewriteCond %{HTTP_USER_AGENT} ^ExtractorPro [OR]',
                'RewriteCond %{HTTP_USER_AGENT} ^EyeNetIE [OR]',
                'RewriteCond %{HTTP_USER_AGENT} ^FlashGet [OR]',
                'RewriteCond %{HTTP_USER_AGENT} ^GetRight [OR]',
                'RewriteCond %{HTTP_USER_AGENT} ^GetWeb! [OR]',
                'RewriteCond %{HTTP_USER_AGENT} ^Go!Zilla [OR]',
                'RewriteCond %{HTTP_USER_AGENT} ^Go-Ahead-Got-It [OR]',
                'RewriteCond %{HTTP_USER_AGENT} ^GrabNet [OR]',
                'RewriteCond %{HTTP_USER_AGENT} ^Grafula [OR]',
                'RewriteCond %{HTTP_USER_AGENT} ^HMView [OR]',
                'RewriteCond %{HTTP_USER_AGENT} HTTrack [NC,OR]',
                'RewriteCond %{HTTP_USER_AGENT} ^Image\ Stripper [OR]',
                'RewriteCond %{HTTP_USER_AGENT} ^Image\ Sucker [OR]',
                'RewriteCond %{HTTP_USER_AGENT} Indy\ Library [NC,OR]',
                'RewriteCond %{HTTP_USER_AGENT} ^InterGET [OR]',
                'RewriteCond %{HTTP_USER_AGENT} ^Internet\ Ninja [OR]',
                'RewriteCond %{HTTP_USER_AGENT} ^JetCar [OR]',
                'RewriteCond %{HTTP_USER_AGENT} ^JOC\ Web\ Spider [OR]',
                'RewriteCond %{HTTP_USER_AGENT} ^larbin [OR]',
                'RewriteCond %{HTTP_USER_AGENT} ^LeechFTP [OR]',
                'RewriteCond %{HTTP_USER_AGENT} ^Mass\ Downloader [OR]',
                'RewriteCond %{HTTP_USER_AGENT} ^MIDown\ tool [OR]',
                'RewriteCond %{HTTP_USER_AGENT} ^Mister\ PiX [OR]',
                'RewriteCond %{HTTP_USER_AGENT} ^Navroad [OR]',
                'RewriteCond %{HTTP_USER_AGENT} ^NearSite [OR]',
                'RewriteCond %{HTTP_USER_AGENT} ^NetAnts [OR]',
                'RewriteCond %{HTTP_USER_AGENT} ^NetSpider [OR]',
                'RewriteCond %{HTTP_USER_AGENT} ^Net\ Vampire [OR]',
                'RewriteCond %{HTTP_USER_AGENT} ^NetZIP [OR]',
                'RewriteCond %{HTTP_USER_AGENT} ^Octopus [OR]',
                'RewriteCond %{HTTP_USER_AGENT} ^Offline\ Explorer [OR]',
                'RewriteCond %{HTTP_USER_AGENT} ^Offline\ Navigator [OR]',
                'RewriteCond %{HTTP_USER_AGENT} ^PageGrabber [OR]',
                'RewriteCond %{HTTP_USER_AGENT} ^Papa\ Foto [OR]',
                'RewriteCond %{HTTP_USER_AGENT} ^pavuk [OR]',
                'RewriteCond %{HTTP_USER_AGENT} ^pcBrowser [OR]',
                'RewriteCond %{HTTP_USER_AGENT} ^RealDownload [OR]',
                'RewriteCond %{HTTP_USER_AGENT} ^ReGet [OR]',
                'RewriteCond %{HTTP_USER_AGENT} ^SiteSnagger [OR]',
                'RewriteCond %{HTTP_USER_AGENT} ^SmartDownload [OR]',
                'RewriteCond %{HTTP_USER_AGENT} ^SuperBot [OR]',
                'RewriteCond %{HTTP_USER_AGENT} ^SuperHTTP [OR]',
                'RewriteCond %{HTTP_USER_AGENT} ^Surfbot [OR]',
                'RewriteCond %{HTTP_USER_AGENT} ^tAkeOut [OR]',
                'RewriteCond %{HTTP_USER_AGENT} ^WWW-Mechanize [OR]',
                'RewriteCond %{HTTP_USER_AGENT} ^Teleport\ Pro [OR]',
                'RewriteCond %{HTTP_USER_AGENT} ^VoidEYE [OR]',
                'RewriteCond %{HTTP_USER_AGENT} ^Web\ Image\ Collector [OR]',
                'RewriteCond %{HTTP_USER_AGENT} ^Web\ Sucker [OR]',
                'RewriteCond %{HTTP_USER_AGENT} ^WebAuto [OR]',
                'RewriteCond %{HTTP_USER_AGENT} ^WebCopier [OR]',
                'RewriteCond %{HTTP_USER_AGENT} ^WebFetch [OR]',
                'RewriteCond %{HTTP_USER_AGENT} ^WebGo\ IS [OR]',
                'RewriteCond %{HTTP_USER_AGENT} ^WebLeacher [OR]',
                'RewriteCond %{HTTP_USER_AGENT} ^WebReaper [OR]',
                'RewriteCond %{HTTP_USER_AGENT} ^WebSauger [OR]',
                'RewriteCond %{HTTP_USER_AGENT} ^Website\ eXtractor [OR]',
                'RewriteCond %{HTTP_USER_AGENT} ^Website\ Quester [OR]',
                'RewriteCond %{HTTP_USER_AGENT} ^WebStripper [OR]',
                'RewriteCond %{HTTP_USER_AGENT} ^WebWhacker [OR]',
                'RewriteCond %{HTTP_USER_AGENT} ^WebZIP [OR]',
                'RewriteCond %{HTTP_USER_AGENT} ^Widow [OR]',
                'RewriteCond %{HTTP_USER_AGENT} ^WWWOFFLE [OR]',
                'RewriteCond %{HTTP_USER_AGENT} ^Xaldon\ WebSpider [OR]',
                'RewriteCond %{HTTP_USER_AGENT} ^Toata\ dragostea\ mea\ pentru\ diavola [OR]',
                'RewriteCond %{HTTP_USER_AGENT} ^Mozilla/5.0\ SF [OR]',
                'RewriteCond %{HTTP_USER_AGENT} ^Zeus [OR]',
                // SCANNER PROTECTION
                'RewriteCond %{HTTP_USER_AGENT} ^w3af.sourceforge.net [NC,OR]',
                'RewriteCond %{HTTP_USER_AGENT} dirbuster [NC,OR]',
                'RewriteCond %{HTTP_USER_AGENT} nikto [NC,OR]',
                'RewriteCond %{HTTP_USER_AGENT} sqlmap [NC,OR]',
                'RewriteCond %{HTTP_USER_AGENT} fimap [NC,OR]',
                'RewriteCond %{HTTP_USER_AGENT} nessus [NC,OR]',
                'RewriteCond %{HTTP_USER_AGENT} whatweb [NC,OR]',
                'RewriteCond %{HTTP_USER_AGENT} Openvas [NC,OR]',
                'RewriteCond %{HTTP_USER_AGENT} jbrofuzz [NC,OR]',
                'RewriteCond %{HTTP_USER_AGENT} libwhisker [NC,OR]',
                'RewriteCond %{HTTP_USER_AGENT} webshag [NC,OR]',
                'RewriteCond %{HTTP_USER_AGENT} (havij|Netsparker|libwww-perl|python|nikto|curl|scan|java|winhttp|clshttp|loader) [NC,OR]',
                'RewriteCond %{HTTP_USER_AGENT} (%0A|%0D|%27|%3C|%3E|%00) [NC,OR]',
                'RewriteCond %{HTTP_USER_AGENT} (;|<|>|\'|"|\)|\(|%0A|%0D|%22|%27|%28|%3C|%3E|%00).*(libwww-perl|python|nikto|curl|scan|java|winhttp|HTTrack|clshttp|archiver|loader|email|harvest|extract|grab|miner) [NC,OR]',
                'RewriteCond %{HTTP:Acunetix-Product} ^WVS',
                'RewriteCond %{REQUEST_URI} (<|%3C)([^s]*s)+cript.*(>|%3E) [NC,OR]',
                'RewriteCond %{REQUEST_URI} (<|%3C)([^e]*e)+mbed.*(>|%3E) [NC,OR]',
                'RewriteCond %{REQUEST_URI} (<|%3C)([^o]*o)+bject.*(>|%3E) [NC,OR]',
                'RewriteCond %{REQUEST_URI} (<|%3C)([^i]*i)+frame.*(>|%3E) [NC,OR]',
                'RewriteCond %{REQUEST_URI} base64_(en|de)code[^(]*\([^)]*\) [NC,OR]',
                'RewriteCond %{REQUEST_URI} (%0A|%0D|\\r|\\n) [NC,OR]',
                'RewriteCond %{REQUEST_URI} union([^a]*a)+ll([^s]*s)+elect [NC]',
                'RewriteRule ^(.*)$ index.php?bad_traffic=1 [R=301,L]'
			);
			array_splice( $exploded, 3, 0, $my_rules );
			$rules = implode("\n", $exploded);
	  		return $rules;
	}
	flush_rewrite_rules(true);
}

register_deactivation_hook( __FILE__, 'ev_wpblk_wpblock_deactivation');
function ev_wpblk_wpblock_deactivation() {
	flush_rewrite_rules(true);
}


// If you want to change the level of users that are blocked from the admin
// interface you can change this level. For details of the capabilities and what
// they mean see http://codex.wordpress.org/Roles_and_Capabilities#Capabilities
$ev_wpblk_required_capability = 'edit_others_posts';
// Here you can change the url to which users are redirected. If it's left blank
// the plugin will redirect to the blog homepage.
$ev_wpblk_redirect_to = '';

// To make upgrades easier, you can set these in wp-config.php like:
/*
define('EV_WPBLK_REQUIRED_CAPABILITY', 'edit_others_posts');
define('EV_WPBLK_REDIRECT_TO' , 'http://enter-url-here');
*/

// Override these values from the constants if they are defined and not empty
if (defined('EV_WPBLK_REQUIRED_CAPABILITY'))
	$ev_wpblk_required_capability = EV_WPBLK_REQUIRED_CAPABILITY;
if (defined('EV_WPBLK_REDIRECT_TO'))
	$ev_wpblk_redirect_to = EV_WPBLK_REDIRECT_TO;

if (!function_exists('ev_wpblk_init')) {
	function ev_wpblk_init() {
		// We need the config vars inside the function
		global $ev_wpblk_required_capability, $ev_wpblk_redirect_to;

		// Is this the admin interface?
		if ( stripos($_SERVER['REQUEST_URI'],'/wp-admin/') !== false && stripos($_SERVER['REQUEST_URI'],'async-upload.php') == false && stripos($_SERVER['REQUEST_URI'],'admin-ajax.php') == false ) {
			if (!current_user_can($ev_wpblk_required_capability)) {
			// If you want to use this plugin on WPMU to stop all users accessing the admin interface, comment out the line above, uncomment the line below.
			//if (!is_site_admin()) {
				// Do we need to default to the site homepage?
				if ($ev_wpblk_redirect_to == '') { $ev_wpblk_redirect_to = get_option('home'); }
				wp_redirect($ev_wpblk_redirect_to,302);
			}
		}
	}
}

// Add the action with maximum priority
add_action('init','ev_wpblk_init',0);
