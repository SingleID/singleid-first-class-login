<?php
/**
 * Plugin Name: SingleID First-class Login Experience
 * Plugin URI: https://github.com/SingleID/singleid-first-class-login/
 * Description: Enjoy the first-class login experience for your wordpress backoffice
 * Version: 1.0
 * Author: SingleID Inc.
 * Author URI: http://www.singleid.com
 * License: GPL2
 * 
 * SingleID First-class Login Experience is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or any later version.
 * 
 * SingleID First-class Login Experience is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with SingleID First-class Login Experience.
 * If not, see http://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html
 * 
 */


/* Internal note
* add new translation !
* comaptibility check
* 
* 
* 
* Future features
* 
* possibility to associate than one SingleID to login with a specific user
* update profile infos at every login? only optionally
* multisite testing
* Better handling this cas: username already exist? 
* 

*/




defined('ABSPATH') or die('No script kiddies');

define( 'WP_DEBUG', false ); // only for debugging purposes

define('SINGLEID_SERVER_URL', 'https://app.singleid.com/');
define('SINGLEID_DEFINED_ENCRYPTED_RANDOM', get_option('singleid_tmp_password_for_auth'));
															// this temporary encryption makes no sense because the idea does his job (defending users' privacy against DB dump) only if this temporary password is NOT stored on the same DB.
															// So it's here only as cross compatibility with the main plugin specs and maybe will be removed asap.
require('lib/password.php'); // needed for php =< 5.5 but >= 5.3.3

global $singleid_fcl_db_version;

$singleid_fcl_db_version = '1.0';

add_filter( 'allowed_http_origin', '__return_true' ); // needed for allowing post data from the user's App

add_filter( 'plugin_row_meta', 'singleid_custom_plugin_row_meta', 10, 2 );

function singleid_custom_plugin_row_meta( $links, $file ) {

	if ( strpos( $file, 'singleid-first-class-login.php' ) !== false ) {
		$links[] = '<a href="options-general.php?page=singleid-options">Settings</a>';
		$links[] = '<a href="https://github.com/SingleID/singleid-first-class-login/blob/master/UserFaq.md">User FAQ</a>';
	}
	
	return $links;
}

function singleid_fcl_install() {
	
	
	//Check minimum PHP requirements, which is 5.3.3 at the moment.
	if (version_compare(PHP_VERSION, "5.3.3", "<")) {
		add_action('admin_notices', 'singleid_AddPhpVersionError');
		$fail = true;
	}

	//Check minimum WP requirements, which is 3.3 at the moment.
	if (version_compare($GLOBALS["wp_version"], "3.3", "<")) {
		add_action('admin_notices', 'singleid_AddWpVersionError');
		$fail = true;
	}
	
    
    if (is_multisite()) {
        error_log('Not yet tested on multisite (2015-09-16)');
        add_action('admin_notices', 'singleid_AddWpMultiError');
		$fail = true;
    }
    
    
    
    if ($fail) {
		wp_die('Sorry. You Wordpress is not compatible!');
	}
	
    
    global $wpdb;
    global $singleid_fcl_db_version;
    
    $table_data = $wpdb->prefix . 'SingleID_users_raw_data';
    // Please note the memory engine! We doens't need to store permanently these data.
    // The login behind is that a full DB dump should not help an hacker to log as a registered user
    
    $sql = "CREATE TABLE IF NOT EXISTS $table_data (
	  `SingleID` char(8) COLLATE utf8_unicode_ci NOT NULL,
	  `UTID` char(32) COLLATE utf8_unicode_ci NOT NULL,
	  `bcrypted_UTID` CHAR( 60 ) CHARACTER SET latin1 COLLATE latin1_bin NOT NULL,
	  `bcrypted_hash_check` CHAR( 60 ) CHARACTER SET latin1 COLLATE latin1_bin NOT NULL,
	  `right_now` INT( 11 ) UNSIGNED NOT NULL,
	  `start_ip` varchar(60) COLLATE utf8_unicode_ci NOT NULL,
	  `role` varchar(32) COLLATE utf8_unicode_ci NOT NULL,
	  `rawdata_received` varchar(8000) COLLATE utf8_unicode_ci NOT NULL,
	  `encrypted_data` varchar(8000) COLLATE utf8_unicode_ci NOT NULL,
	  `sending_ip` varchar(60) COLLATE utf8_unicode_ci NOT NULL,
	  `WpUserId` INT( 11 ) UNSIGNED NOT NULL,
	  UNIQUE KEY `bcrypted_UTID` (`bcrypted_UTID`),
	  KEY `UTID` (`UTID`)
	) ENGINE=MEMORY DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;";
    
    require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
    
    dbDelta($sql);
    
    add_option('singleid_fcl_db_version', $singleid_fcl_db_version);
    
    $tmp_password_for_auth = singleid_random_chars(16);
    add_option('singleid_tmp_password_for_auth', $tmp_password_for_auth, '', 'yes');
    
    $random_install_key = singleid_random_chars(16);
    add_option('singleid_random_install_key', $random_install_key, '', 'yes');
    
    
}



function singleid_hide_buttons() {
	// the old "add new" users button should be removed to avoid confusion
	// this should be optional in a future release of this plugin
    global $current_screen;
    
    if ($current_screen->id == 'users') {
        echo '<style>.add-new-h2{display: none;}</style>'; 
    }
    
}
add_action('admin_head', 'singleid_hide_buttons');




// Add the admin page
function singleid_add_users_page() {
    global $current_user;
    
    add_users_page(
    // $page_title
        'Your data'
    // $menu_title
        , 'Add New'
    // $capability
        , 'read'
    // $menu_slug
        , 'add_new_singleid_user', 'singleid_render_users_page');
    
    
    remove_submenu_page('users.php', 'user-new.php'); // be careful about privileges!
    
    
}
add_action('admin_menu', 'singleid_add_users_page');



// Render the users page
function singleid_render_users_page() {
    global $current_user;
    
    if (!current_user_can('read', $current_user->ID))
        return;
    
    
    if (is_multisite()) {
        if (!current_user_can('create_users') && !current_user_can('promote_users'))
            wp_die(__('Cheatin&#8217; uh?'), 403);
    } elseif (!current_user_can('create_users')) {
        wp_die(__('Cheatin&#8217; uh?'), 403);
    }
    
    // should be enough?
    
    
?>
<div class="wrap">
	<form method="POST" action="<?php 
    echo admin_url('admin.php');
?>">

		<table class="form-table">
			
		<tr>
			<th scope="row">SingleID</th>
			<td colspan="3">
			<input type="text" id="SingleID" name="SingleID" value="" />
			<br /><span class="description"><?php
    _e('Users will receive an handshake request in order to create an account');
?></span>
			</td>
		</tr>
			
		
		<tr class="form-field">
			<th scope="row"><label for="role"><?php
    _e('Role');
?></label></th>
			<td><select name="role" id="role">
				<?php
    if (!$new_user_role)
        $new_user_role = !empty($current_role) ? $current_role : get_option('default_role');
    wp_dropdown_roles($new_user_role);
?>
				</select>
			</td>
		</tr>
		<?php
    if (is_multisite() && is_super_admin()) {
?>
		<tr>
			<th scope="row"><label for="noconfirmation"><?php
        _e('Skip Confirmation Email');
?></label></th>
			<td><label for="noconfirmation"><input type="checkbox" name="noconfirmation" id="noconfirmation" value="1" <?php
        checked($new_user_ignore_pass);
?> /> <?php
        _e('Add the user without sending an email that requires their confirmation.');
?></label></td>
		</tr>
		<?php
    }
?>
						

		</table>
		
		<p class="submit">
		<input type="hidden" name="action" value="singleid_add_new" />
		<input type="submit" value="Add New" class="button-primary" />
		</p>		
	</form>
</div>
<?php
    
    
    
    
    
}





add_action('admin_action_singleid_add_new', 'singleid_add_new_admin_action');
function singleid_add_new_admin_action($who, $existing_user_id = 0) {
	
    global $wpdb;
    // creating new user and requesting a first handshake to the device
    
    if (singleid_is_SingleID($who)) {
		$SingleID = $who;	// when we edit an user
	} else {
		$SingleID = $_POST['SingleID'];	//when we add a new user
	}
    
    // error_log('We are creating a first handshake with '.$SingleID);
    
	$ssl = singleid_check_ssl();
    
    $UTID = singleid_random_chars(16);
    
    $options = Array(
        'cost' => 12
    );
    
    
    $UTID_bcrypted = password_hash($UTID, PASSWORD_BCRYPT, $options);
    
    
    
    $table_data = $wpdb->prefix . 'SingleID_users_raw_data';
    
    $wpdb->insert($table_data, array(
        'SingleID' => $SingleID,
        'UTID' => md5($UTID), // we do not need the UTID in clear text saved but we need an index for the DB. a data dump cannot help to stole this device
        'start_ip' => singleid_gimme_visitor_ip(),
        'bcrypted_UTID' => $UTID_bcrypted,
        'right_now' => time(),
        'role' => $_POST['role'],
        'WpUserId' => $existing_user_id
    ));
    
    
    $title_name = get_bloginfo('name') . ' ' . get_bloginfo('description');
    
    if ($title_name == ' ') {
        $title_name = get_bloginfo('wpurl');
    }
    
    // $logo_desiderato = get_option( 'singleid_logo_url');
    // error_log('logo desiderato ->: '.$logo_desiderato);
    
    // $logo_url = get_bloginfo( 'template_directory' ) .'/images/logo.jpg';
    
    //set POST variables
    $fields_string = '';
    // url encode ?
    $fields        = array(
        'SingleID' => $SingleID, // the value typed in the button ( 8 hex char string )
        'UTID' => $UTID, // MUST BE AN MD5 HASH or a 32 hex char string
        'logo_url' => 'http://singleid.com/wp-content/themes/singleid/img/logonew.png', // get_option( 'singleid_logo_url'), // the img that will be displayed on the user device
        'name' => 'handshake:' . $title_name, // website name
        'requested_data' => '1,4,5',
        'ssl' => $ssl,
        'url_waiting_data' => admin_url('admin-ajax.php'),
        'ACTION_ID' => 'askfordata'
    );
    
    
    
    
    //url-ify the data for the POST
    foreach ($fields as $key => $value) { // TODO !!!!TODO!!!! and if a var contain a & ? DOUBLE CHECK HERE ASAP
        $fields_string .= $key . '=' . $value . '&'; // TODO TO CHECK 
    }
    rtrim($fields_string, '&');
    
    error_log($fields_string);
    
    $ServerReply = singleid_send_request_to_singleid_server($fields, $fields_string);
    
    
    if ($ServerReply['Reply'] <> 'ok') {
        wp_die(serialize($ServerReply)); // hopefully an user should never see this.
        // if you are here means that the SingleID servers are down or misconfigurated
    }
    
    
    
    wp_redirect($_SERVER['HTTP_REFERER']);
    exit();
}







function singleid_do_not_use_this_page($user) {
    
    echo '<h2>Ops...</h2>
    <h1>You <i>should</i> use the SingleID Add New User page instead of this!</h1><hr>';
    
}

function singleid_custom_user_profile_fields($user) {  // -> check also singleid_save_custom_user_profile_fields
?>
    <h3>First-Class login with SingleID for <?php
    echo esc_attr(get_the_author_meta('user_login', $user->ID));
?></h3>
    <table class="form-table">
        <tr>
            <th scope="row"><label for="SingleID">SingleID</label></th>
            <td>
                <input type="text" class="regular-text" name="SingleID" value="<?php
    echo esc_attr(get_the_author_meta('SingleID', $user->ID));
?>" id="SingleID" /><br />
                <span class="description">Enable login with SingleID App</span>
            </td>
        </tr>
    </table>
    
<?php
}


add_action('show_user_profile', 'singleid_custom_user_profile_fields');
add_action('edit_user_profile', 'singleid_custom_user_profile_fields');
add_action('user_new_form_tag', 'singleid_do_not_use_this_page');


function singleid_save_custom_user_profile_fields($user_id) {
    // do this only if you can
    if (!current_user_can('manage_options'))
        return false;
    
    
    error_log('regarding this user: '.$user_id);
    // check if this usermeta is now different if yes delete the saved handshake
    $current_singleid = esc_attr(get_the_author_meta('SingleID', $user_id));
    
    
    error_log('we have this singleid stored: '.$current_singleid);
    
    
		if ( $current_singleid == $_POST['SingleID']) {
			// nothing to do ;-)!
		} else {
			
			error_log(' DIFFERENT -> handshake requested!');
			
			// if is empty we remove and stop!
			
			// we need to update SingleID_paired and so we need a new handshake requests
			// prevent more than one SingleID! // TODO !
			// check that SingleID are unique into the DB (password-sharing is scheduled for a next release of this plugin)
			
			// save *my* custom field
			update_usermeta($user_id, 'SingleID', $_POST['SingleID']);
			
			if (singleid_is_SingleID($_POST['SingleID'])){	// needed to avoid fake request also "null" value
			
				singleid_add_new_admin_action($_POST['SingleID'], $user_id); // is an update of an existing user!
			
			}
		}
    
    
}

add_action('user_register', 'singleid_save_custom_user_profile_fields');
add_action('personal_options_update', 'singleid_save_custom_user_profile_fields'); 	//for profile page update
add_action('edit_user_profile_update', 'singleid_save_custom_user_profile_fields'); //for profile page update










register_activation_hook(__FILE__, 'singleid_fcl_install');





function singleid_include_js_and_css() {
    global $UTID_bcrypted;
    
    wp_enqueue_script('SingleID_jquery', '//ajax.googleapis.com/ajax/libs/jquery/1.6.1/jquery.min.js');
    wp_enqueue_script('SingleID_plugin', plugins_url('js/plugin.js', __FILE__));
    wp_enqueue_script('jquery_cookie', '//cdnjs.cloudflare.com/ajax/libs/jquery-cookie/1.4.1/jquery.cookie.min.js');
    wp_enqueue_style('SingleID_css', plugins_url('css/SingleID/SingleID.css', __FILE__));
    
    
}

add_action('login_enqueue_scripts', 'singleid_include_js_and_css');





function singleid_login_button() {
    
    $path = plugin_dir_url(__FILE__);
    
    echo singleid_print_login_button('en', '1,4,5');
    
}


add_filter('login_message', 'singleid_login_button');


add_action('login_head', 'singleid_pluginname_ajaxurl');

function singleid_pluginname_ajaxurl() {
    
    $ajax_nonce = wp_create_nonce('SingleID-browser-requests'); // pseudo-useless...
    
?>
<script type="text/javascript">
var ajaxurl = '<?php
    echo admin_url('admin-ajax.php');
?>';
var ajaxnonce = '<?php
    echo $ajax_nonce;
?>';
var ajaxadminurl = '<?php
    echo admin_url();
?>';
</script>
<?php
}



add_action('wp_ajax_first_class_login_error', 'singleid_first_class_login_error_callback');

function singleid_first_class_login_error_callback() {
	// Are you trying to log-in but you are already logged in!
    wp_die('You are already Logged!');
}



add_action('wp_ajax_nopriv_first_class_login', 'singleid_first_class_login_callback');

function singleid_first_class_login_callback() {
    
    global $wpdb; // db needed
    
    check_ajax_referer('SingleID-browser-requests', 'security');
    
    if (!singleid_is_SingleID($_POST['single_id'])) {
        wp_die('501'); // TODO should be checked *also* from JS!
    }
    // From Browser: user has just clicked go!
    // here start the request from the website to the SingleID Server
    
    $options = Array(
        'cost' => 12
    );
    
    
    if ($_POST['optionalAuth'] <> '[]') {
        
        require('lib/GibberishAES.php');
        
        $hashed_check = password_hash(md5(stripslashes($_POST['optionalAuth'])), PASSWORD_BCRYPT, $options);
        
        GibberishAES::size(256);
        $encrypted_secret_string = GibberishAES::enc(stripslashes($_POST['optionalAuth']), SINGLEID_DEFINED_ENCRYPTED_RANDOM); // TODO
        
    }
    
    
    $UTID = singleid_random_chars(16);
    
    
    // noone can crack a bcrypt hash of a 32 (hex)char string during the 10 minutes of his validity
    // so using an higher cost value is useless
    
    $UTID_bcrypted = password_hash($UTID, PASSWORD_BCRYPT, $options);
	
	//error_log('saved enc action' . $encrypted_secret_string);
    
    $table_data = $wpdb->prefix . 'SingleID_users_raw_data';
    
    $wpdb->insert($table_data, array(
        'SingleID' => $_POST['single_id'],
        'UTID' => $UTID,
        'start_ip' => singleid_gimme_visitor_ip(),
        'bcrypted_UTID' => $UTID_bcrypted,
        'right_now' => time(),
        'bcrypted_hash_check' => $hashed_check,
        'encrypted_data' => $encrypted_secret_string
    ));
    
    setcookie('bcry', $UTID_bcrypted, time() + 60 * 10, '/'); // js will refresh over ajax using the bcrypted value as key
    // this is needed because the UTID must not be know from the browser as SingleID flow require!
    
    
    
	$ssl = singleid_check_ssl();
    
    
    $title_name = get_bloginfo('name') . ' ' . get_bloginfo('description');
    
    if ($title_name == ' ') {
        $title_name = get_bloginfo('wpurl');
    }
    
    //error_log('Title name should be ' . $title_name);
    
    
    //set POST variables
    $fields_string = '';
    // url encode ?
    $fields        = array(
        'SingleID' => $_POST['single_id'], // the value typed in the button ( 8 hex char string )
        'UTID' => $UTID, // MUST BE AN MD5 HASH or a 32 hex char string
        'logo_url' => 'http://www.vantax.eu/index3_files/697933-0-android.png', // get_option( 'singleid_logo_url'), // the img that will be displayed on the user device
        'name' => $title_name, // website name
        'requested_data' => '1,4,6',
        'ssl' => $ssl,
        'url_waiting_data' => admin_url('admin-ajax.php'),
        'ACTION_ID' => 'askfordata'
    );
    
    
    
    
    //url-ify the data for the POST
    foreach ($fields as $key => $value) { // TODO !!!!TODO!!!! and if a var contain a & ? DOUBLE CHECK HERE ASAP
        $fields_string .= $key . '=' . $value . '&'; // TODO TO CHECK 
    }
    rtrim($fields_string, '&');
    
    // error_log($fields_string);
    
    $ServerReply = singleid_send_request_to_singleid_server($fields, $fields_string);
    
    
    if ($ServerReply['Reply'] <> 'ok') {
        wp_die($ServerReply['PopupTitle']); // hopefully an user should never see this.
        // if you are here means that the SingleID servers are down or misconfigurated
    }
    
    
    wp_die('100');
    
    
    
}









add_action('wp_ajax_nopriv_first_class_login_refresh', 'singleid_first_class_login_refresh_callback');

function singleid_first_class_login_refresh_callback() { 	// browser is waiting and refreshing
															// this is not involved when we do the first handshake
    global $wpdb;
    $table_data = $wpdb->prefix . 'SingleID_users_raw_data';
    
    // Check if is a valid bcrypt with cost between 12 and 19
    if (!singleid_is_bcrypt($_POST['bcryptutid'])) {
        wp_die('501');
    }
    
    $sql = "SELECT * FROM $table_data WHERE bcrypted_UTID = '" . $_POST['bcryptutid'] . "'";
    $result = $wpdb->get_row($sql) or die(mysql_error());
    
    
    if (password_verify($result->UTID, $_POST['bcryptutid'])) {
        
        if ($result->rawdata_received <> '') { // the file exist ! // TODO!
            // TODO we need to parse rawdata!!!
            // which user we need to authenticate? the corresponding one of course...
            
            ///////$which_user = esc_attr( get_the_author_meta( 'SingleID', $user->ID ) )
            
            if (!empty($result->SingleID))
                $user = reset(get_users(array(
                    'meta_key' => 'SingleID',
                    'meta_value' => $result->SingleID,
                    'number' => 1,
                    'count_total' => false
                )));
            
            if (!isset($user->user_login, $user)) {
                // UGLY, we need to inform users better! // also for multiple occurency
                wp_die('502');
            } else {
                $userlogin = $user->user_login;
            }
            
            singleid_programmatic_login($userlogin);
            
            wp_die('200'); // The UTID has been forwarded to the smartphone and now is coming back!
            
        } else {
            
            wp_die('100'); // continue... misuse as refresh
            
        }
        
        
    } else {
        
        
        $now = time();
        
        if (($now - $result->right_now) > 180) {
            wp_die('400'); // too much time is passed
            // error_log ( " $now - $result->right_now ");
            // the output number code are inspired from the http status code and are read by the .js
        }
        
        
        wp_die('100'); // continue... misuse as refresh
        // increase some counter on db....
    }
    
    
}


add_action('wp_ajax_nopriv_wp_hook', 'singleid_wp_hook_callback'); 

function singleid_wp_hook_callback() { // Handling replies from App
	
    global $wpdb;
    $table_data = $wpdb->prefix . 'SingleID_users_raw_data';
    // first we should check if is replying to a recent requests
    
    // then we have to check if there is already a paired value on the DB to encrypt any following requestes
    
    // if not we have to create a random value
    
    if ((singleid_is_SingleID($_POST['SingleID'])) and (!isset($_POST['SharedSecret']))) {
        
        // This is the reply to the 1,4,5 handshake requests.
        // so we need to check if the hash is correct ( and in how many hours? )
        // Check if is a valid bcrypt with cost between 12 and 19
        
        if (!singleid_is_md5($_POST['UTID'])) {
            error_log($_POST['UTID']);
            wp_die('501');
        }
        
        
        // A MITM HERE IS POSSIBLE?	
        // Surely if recipient do not use SSL
        // If SSL is enabled is much more complicated and it involve to hack at least two devices (to explain)
        
        $sql = "SELECT * FROM $table_data WHERE UTID = '" . md5($_POST['UTID']) . "' AND SingleID = '" . $_POST['SingleID'] . "' ORDER BY right_now DESC LIMIT 1";
        $result = $wpdb->get_row($sql) or die(mysql_error());
        
        if (password_verify($_POST['UTID'], $result->bcrypted_UTID)) {
            // TODO in case of same email?!!?!?! now display ko! 2015-09-09
            // and in case
            // we must add a new user on wordpress with the data sent from the device
            
            // wordpress needs: username, email, first name, lastname, website, password(hahaha)
            
            // We must recognize from the SingleID if the user is already existent ( update only needed) or we have to create a new one
            
            // we grab from the SingleID value
            // Pers_first_name, Pers_first_email, Pers_last_name,  
            
            $user_name  = $_POST['Pers_first_name'] . ' ' . $_POST['Pers_last_name'];
            $user_email = $_POST['Pers_first_email'];
            
			$random_password = wp_generate_password($length = 24, $include_standard_special_chars = true);
			// this is a very complex password that the user should never use!
			// btw if the user loose his device can use the forgot password method to recover access
					
					
					
            if ($result->WpUserId == 0) {	// is a request to create a new user!
				
				$user_id = username_exists($user_name);
				
				if (!$user_id and email_exists($user_email) == false) {
					
					// we need to create a new user or we are updating an existing one?
					
					$user_id         = wp_create_user($user_name, $random_password, $user_email);
					
					// Set the nickname with the data grabbed from the device
					wp_update_user(array(
						'ID' => $user_id,
						'nickname' => $_POST['Pers_first_name']
					));
					
					// Set the role
					$user = new WP_User($user_id);
					$user->set_role($result->role);
				
					
					$shared_secret = singleid_random_chars(16);
					
					$options = Array(
						'cost' => 13
					);
					
					$shared_secret_bcrypted = password_hash($shared_secret, PASSWORD_BCRYPT, $options);
					
					// TOFIX HERE - l'utente creato non ha questi valori!
					update_usermeta($user_id, 'SingleID', $_POST['SingleID']);
					update_usermeta($user_id, 'SingleID_paired', $shared_secret_bcrypted);
					
					// we need to reply with a secret password
					// we need to save the hashed password into the meta of the users
					
					wp_die($shared_secret); // the device will store this for any future communications!
					
					
				} else {
					
					$random_password = __('User already exists.  Password inherited.');
				
				}
				
			} elseif ($result->WpUserId > 0) { // is an update of an existing wordpress user
				
					$plugin_options = get_option('SingleID_options');
    
						if ($plugin_options['replace_old_password'] == 1) {
							wp_set_password( $random_password, $result->WpUserId ); // We replace the old user password Better security!
																					// If the user is logged will be immediately disconnected by Wordpress
																					// Disabling the plugin will force any user to follow the "password forgot" procedure !
						}
																			
					$shared_secret = singleid_random_chars(16);
					
					$options = Array(
						'cost' => 13
					);
					
					$shared_secret_bcrypted = password_hash($shared_secret, PASSWORD_BCRYPT, $options);
					
					update_usermeta($result->WpUserId, 'SingleID', $_POST['SingleID']);
					update_usermeta($result->WpUserId, 'SingleID_paired', $shared_secret_bcrypted);
					
					// we need to reply with a secret password
					// we need to save the hashed password into the meta of the users
					
					wp_die($shared_secret); // the device will store this for any future communications!
				
				
			}
            
            
            
        } else {
            wp_die('ko'); // the hash returned from the device is not so good as we expect ;-)
        }
        
        
        wp_die(md5($_POST['SingleID']));
    }
    
    
    
    if (singleid_is_md5($_POST['SharedSecret'])) {
        // This is the first reply to a 1,4,6 request.
        // the smartphone is asking which operation I am authorizing right now? 
        // and we need to reply with the encrypted text (that in the next release should include also a nonce graphical or not?)
        
        $sql = "SELECT * FROM $table_data WHERE UTID = '" . $_POST['UTID'] . "' AND SingleID = '" . $_POST['SingleID'] ."' ORDER BY right_now DESC LIMIT 1"; // TODO order by should be removed because we must store a request at a time
        
        $result = $wpdb->get_row($sql) or die(mysql_error());
        
        $encdata = $result->encrypted_data;
        
        // sure we can optimize it!
        $user = reset(get_users(array(
            'meta_key' => 'SingleID',
            'meta_value' => $result->SingleID,
            'number' => 1,
            'count_total' => false
        )));
        
        //error_log('for which user: '.$user->ID);
        
        $user_paired_value = get_user_meta($user->ID, 'SingleID_paired', true);
        
        //error_log('trying to compare : '.$_POST['SharedSecret'] .' with '.$user_paired_value);
        
        if (password_verify($_POST['SharedSecret'], $user_paired_value)) {
            // the smartphone has given "prove" to know the uncrypted value of the bcrypt ( singleid_paired )
            // TODO this is not really secure because the data are knowable from an attacker
            
            require('lib/GibberishAES.php');
            $decrypted_data = GibberishAES::dec($encdata, SINGLEID_DEFINED_ENCRYPTED_RANDOM);
            // here we re-encrypt the data with the client key if the hash is correct !
            
            GibberishAES::size(256); // Also 192, 128
            
            $encrypted_secret_string = GibberishAES::enc($decrypted_data, $_POST['SharedSecret']);
            
            wp_die($encrypted_secret_string); // the device has the password to decrypt this
            
            // this code is needed to avoid unencrypted infos into the DB
            // maybe in a future release we can remove the temporary password from the DB
            
        } else {
			error_log('WTF? we have no pwd paired with this SingleID!');
			wp_die('ko');
		}
    }
    
    
    if (singleid_is_md5($_POST['unc_hash'])) {
        // This is the second reply to a 1,4,6 request where the user said YES
        // and if unc_hash is the clear md5 hash of the decrypted text we are right!
        // as already said this is not really secure if we haven't a nonce here
        
        $sql = "SELECT * FROM $table_data WHERE UTID = '" . $_POST['UTID'] . "' ORDER BY right_now DESC LIMIT 1"; // TODO order by not needed
        $result = $wpdb->get_row($sql) or die(mysql_error());
        
        if (password_verify($_POST['unc_hash'], $result->bcrypted_hash_check)) {
            // the smartphone was able to give me the md5 of the unencrypted text of the action.
            // so we can authorize the browser right now
            
            $wpdb->update($table_data, array(
                'rawdata_received' => serialize($_POST),
                'sending_ip' => singleid_gimme_visitor_ip()
            ), array(
                'UTID' => $_POST['UTID']
            ));
            
            // error_log('dati ricevuti ' . serialize($_POST));
            
            wp_die('200'); // pseudo useless. Please note that it's read from the App.
            
        } else {
			error_log('unc_hash different from bcrypt');
			wp_die('ko');
		}
        
        
    }
    
    
    
    
    
    
    error_log('YOU SHOULD NOT BE HERE'); // DEBUG
    wp_die(md5($_POST['SingleID']));
    
    
    
    
    
    
    
    
    
    
}

/**
 * Programmatically logs a user in
 * 
 * @param string $username
 * @return bool True if the login was successful; false if it wasn't
 */
function singleid_programmatic_login($username) {
	
    if (is_user_logged_in()) {
        wp_logout();
    }
    
    add_filter('authenticate', 'singleid_allow_programmatic_login', 10, 3); // hook in earlier than other callbacks to short-circuit them
    $user = wp_signon(array(
        'user_login' => $username
    ));
    remove_filter('authenticate', 'singleid_allow_programmatic_login', 10, 3);
    
    if (is_a($user, 'WP_User')) {
        wp_set_current_user($user->ID, $user->user_login);
        
        if (is_user_logged_in()) {
            return true;
        }
    }
    
    return false;
}



/**
 * An 'authenticate' filter callback that authenticates the user using only the username.
 *
 * To avoid potential security vulnerabilities, this should only be used in the context of a programmatic login,
 * and unhooked immediately after it fires.
 * 
 * @param WP_User $user
 * @param string $username
 * @param string $password
 * @return bool|WP_User a WP_User object if the username matched an existing user, or false if it didn't
 */
function singleid_allow_programmatic_login($user, $username, $password) {
	
    return get_user_by('login', $username);

}









function singleid_print_login_button($language = 'en', $requested_data = '1,4,5') {
    
    
    /*
    $label['en']['1']        = 'Login with';
    $label['en']['1,2,3']    = 'Login with';
    $label['en']['1,2,3,4']  = 'Login with';
    $label['en']['1,-2,3']   = 'Login with';
    $label['en']['1,-2,3,4'] = 'Login with';
    $label['en']['1,4,5']    = 'Identify with';
    $label['en']['1,4,6']    = 'Confirm with';
    */
    
    $today = date("Y-m-d H:i:s");		// these infos will be displayed on the user device!
    $ip = singleid_gimme_visitor_ip();
    $rnd = singleid_random_chars(3);	// we definitely should have something better here. Identicon ?
    
    $plugin_options = get_option('SingleID_options');
    
    
    if ($plugin_options['avoid_mixed_login'] == 1) {
		$hideform = '<style>#loginform{display: none;}#nav{display: none;}</style>';
	}
    
    return $hideform. '
        <div class="singleid_button_wrap singleid_pointer">
            <div class="single_text_single_id">Login with</div>
            <div class="icon_box_single_id"><img src="' . plugins_url('css/SingleID/SingleID_logo_key.jpg', __FILE__) . '" alt="No more form filling, no more password" title="SingleID" /></div>
            
            <input type="hidden" id="Date" class="SingleIDAuth" value="' . $today . '">
            <input type="hidden" id="IP" class="SingleIDAuth" value="' . $ip . '">
            <input type="hidden" id="Auth code" class="SingleIDAuth" value="' . $rnd . '">

            <div class="white_back_single_id singleid_invisible">
                <input class="singleid_styled_input" name="SingleID" type="text" value="" maxlength="8" />
                <button type="button" class="icon_box_go" onClick="sid_sendData();">go</button>
            </div>
            
            <div class="singleid_waiting singleid_invisible">waiting for data</div>
            <a href="https://www.singleid.com" target="_top" title="Available for Android, iPhone and Windows Phone"><div class="free_text_single_id">Get SingleID now!</div>
            </a>
        </div>

        ';
}








// Delete db table when deactivate
function singleid_plugin_remove_db() {
	
    global $wpdb;
    
    $table_data = $wpdb->prefix . 'SingleID_users_raw_data';
    $sql        = "DROP TABLE IF EXISTS $table_data;";
    $wpdb->query($sql);
    
    delete_option("singleid_fcl_db_version");
    
    $meta_type  = 'user';
    $user_id    = 0; // This will be ignored, since we are deleting for all users.
    $meta_key   = 'SingleID';
    $meta_value = ''; // Also ignored. The meta will be deleted regardless of value.
    $delete_all = true;
    
    delete_metadata($meta_type, $user_id, $meta_key, $meta_value, $delete_all);
    
    $meta_type  = 'user';
    $user_id    = 0; // This will be ignored, since we are deleting for all users.
    $meta_key   = 'SingleID_paired';
    $meta_value = ''; // Also ignored. The meta will be deleted regardless of value.
    $delete_all = true;
    
    delete_metadata($meta_type, $user_id, $meta_key, $meta_value, $delete_all);
    
    delete_option( 'singleid_tmp_password_for_auth' );	
    delete_option( 'singleid_random_install_key' );		// why not? 
    
}
register_deactivation_hook(__FILE__, 'singleid_plugin_remove_db');








add_action('admin_menu', 'singleid_options_add_pages');

function singleid_options_add_pages() {
	
    add_options_page('SingleID Options', 'SingleID Options', 'manage_options', 'singleid-options', 'SingleID_options_page');
    register_setting('SingleID_options', 'SingleID_options');
    
}




// Default option of this plugin

function singleid_options_defaults() {
    // set defaults
    $defaults = array(
        'fastloginonly' => 1,
        'first_handshake_needed' => 1,
        'avoid_mixed_login' => 1,
        'replace_old_password' => 0
    );
    
    add_option('singleid_options', $defaults, '', 'yes');
}

register_activation_hook(__FILE__, 'singleid_options_defaults');



// Setting up options for use in the form 

function singleid_options_page() {
?>
<div class="wrap">
	<form method="post" id="SingleID_options" action="options.php">
		<?php
    settings_fields('SingleID_options');
    $options = get_option('SingleID_options');
?>
		<h2><?php
    _e('SingleID Options');
?></h2>
		
		<h4>More option will be added. Do your requests on <a href="https://github.com/SingleID/singleid-first-class-login">github</a> </h4>

		<table class="form-table">
		
			
			
			<tr>
				<th scope="row"><?php
    _e('Allow only login with SingleID');
?></th>
				<td colspan="3">
				<p>	<label>
						<input name="SingleID_options[fastloginonly]" type="checkbox" value="1" <?php
    checked($options['fastloginonly'], 1);
?>/>
						<?php
    _e('Users\' will not be able to login with the password. But if they click on "password forgotten" they will receive an email with a new password');
?>
					</label></p>
				</td>
			</tr>
			
			<tr>
				<th scope="row"><?php
    _e('Disable actual password');
?></th>
				<td colspan="3">
				<p>	<label>
						<input name="SingleID_options[replace_old_password]" type="checkbox" value="1" <?php
    checked($options['replace_old_password'], 1);
?>/>
						<?php
    _e('Disabling the plugin in future will force any SingleID user to follow the "password forgot" procedure');
?>
					</label></p>
				</td>
			</tr>
			
			<tr>
				<th scope="row"><?php
    _e('Disable old login form for any user');
?></th>
				<td colspan="3">
				<p>	<label>
						<input name="SingleID_options[avoid_mixed_login]" type="checkbox" value="1" <?php
    checked($options['avoid_mixed_login'], 1);
?>/>
						<?php
    _e('Any user must have SingleID to login into backoffice');
?>
					</label></p>
				</td>
			</tr>
			
	<!--		
			<tr>
				<th scope="row"><?php
    _e('Allow login only if smartphone is using the same network of the browser');
?></th>
				<td colspan="3">
				<p>	<label>
						<input name="SingleID_options[sameip]" type="checkbox" value="0" <?php
    checked($options['sameip'], 1);
?>/>
						<?php
    _e('Really secure but with some disadvantages');
?>
					</label></p>
				</td>
			</tr>
	-->		

		</table>
		
		<p class="submit">
		<input type="submit" value="<?php
    echo esc_attr_e('Update Options');
?>" class="button-primary" />
		</p>		
	</form>
</div>
<?php
    
    
    
    
    
}



register_uninstall_hook(__FILE__, 'singleid_delete_simple_options');

function singleid_delete_simple_options() {
	
    delete_option( 'SingleID_options' );
    delete_option( 'singleid_random_install_key' );
    
}








function singleid_gimme_visitor_ip() {
    
    // we all know that an ip could be spoofed and so ? What do you suggest ?
    if (isset($_SERVER['HTTP_X_FORWARDED_FOR']) && $_SERVER['HTTP_X_FORWARDED_FOR']) {
        $ip = $_SERVER['HTTP_X_FORWARDED_FOR']; // behind amazon load balancing
    } else {
        $ip = $_SERVER['REMOTE_ADDR'];
    }
    
    $ip = filter_var($ip, FILTER_VALIDATE_IP);
    $ip = ($ip === false) ? '0.0.0.0' : $ip;
    
    return $ip;
}




function singleid_send_request_to_singleid_server($fields, $fields_string) {
    
    // sometimes we have to remove older entries from DB!
    $not_always = rand(1, 30);
    
    if ($not_always == 1) {
		global $wpdb;
		$now = time();
		$table_data = $wpdb->prefix . 'SingleID_users_raw_data';
		$sql        = "DELETE FROM `$table_data` WHERE right_now < " .($now - 600);
		$wpdb->query($sql);
		$sql        = "ALTER TABLE `$table_data` ENGINE=MEMORY";	// free memory needed
		$wpdb->query($sql);
	}
    
    $ip = singleid_gimme_visitor_ip();
    
    $authh = get_option('singleid_random_install_key');
	// $emailadmin = bloginfo('admin_email');
    $emailadmin = 'privacy-needed'; // should be opt-in
    
    $headers = array(
        'Authorization: ' . $authh,
        'Browser_ip: ' . $ip,
        'admin_contact: ' . $emailadmin
    );
    
    //open connection
    $ch = curl_init();
    
    //set the url, number of POST vars, POST data
    
    
    curl_setopt($ch, CURLOPT_TIMEOUT, 20);
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 20);
    curl_setopt($ch, CURLOPT_URL, SINGLEID_SERVER_URL);
    curl_setopt($ch, CURLOPT_POST, count($fields));
    curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $fields_string);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    
    //execute post
    $result       = curl_exec($ch);
    $responseInfo = curl_getinfo($ch);
    $ServerReply  = json_decode($result, true);
    curl_close($ch); //close connection because we are good guys 
    
    return $ServerReply;
}






function singleid_is_SingleID($val) {
    return (bool) preg_match("/[0-9a-f]{8}$/i", $val);
}

function singleid_is_md5($val) {
    return (bool) preg_match("/[0-9a-f]{32}$/i", $val);
}

function singleid_is_bcrypt($val) { // (allow cost from 12 to 19 only)
    return (bool) preg_match("/^\\$2y\\$[1]{1}[23456789]{1}\\$.[a-zA-Z0-9$\\/.]{52}$/", $val);
}

function singleid_random_chars($length) {
    
    if (function_exists('openssl_random_pseudo_bytes')) {
        $Bytes = openssl_random_pseudo_bytes($length, $strong);
    }
    if ($strong !== true) {
        die('Use PHP >= 5.3 or Mcrypt extension');
    }
    
    return bin2hex($Bytes);
}

function singleid_check_ssl() {
	
	if (!empty($_SERVER['HTTP_X_FORWARDED_PROTO'])) { // needed for cloudflare flexible ssl
        $root .= $_SERVER['HTTP_X_FORWARDED_PROTO'] . '://';
    } else {
        $root .= !empty($_SERVER['HTTPS']) ? "https://" : "http://";
    }
    
    if ($root == 'https://') {
        $ssl = 1;
    } else {
        $ssl = 0;
    }
    
    
    
    if (($ssl == 0) and (get_option('singleid_requested_data') <> '1')) { // { will be blocked ALSO server side }
        error_log('SSL needed! ' . $ssl);
        // DEBUG ONLY // wp_die('SSL Misconfiguration');
    }
    
    return $ssl;
    
}





/**
 * Adds a notice to the admin interface that the WordPress version is too old for the plugin
 *
 */
function singleid_AddWpVersionError() {
	echo "<div id='sm-version-error' class='error fade'><p><strong>" . __('Your WordPress version is too old for SingleID plugin.', 'singleid-first-class-login') . "</strong><br /> " . sprintf(__('Unfortunately this release of SingleID plugin requires at least WordPress %4$s. You are using Wordpress %2$s, which is out-dated and insecure. Please upgrade or go to <a href="%1$s">active plugins</a> and deactivate the SingleID plugin to hide this message.', 'singleid-first-class-login'), "plugins.php?plugin_status=active", $GLOBALS["wp_version"], "https://www.singleid.com/","3.3") . "</p></div>";
}

/**
 * Adds a notice to the admin interface that the WordPress version is too old for the plugin
 *
 */
function singleid_AddPhpVersionError() {
	echo "<div id='sm-version-error' class='error fade'><p><strong>" . __('Your PHP version is too old for SingleID plugin.', 'singleid-first-class-login') . "</strong><br /> " . sprintf(__('Unfortunately this release of SingleID plugin requires at least PHP %4$s. You are using PHP %2$s, which is out-dated and insecure. Please ask your web host to update your PHP installation', 'singleid-first-class-login'), "plugins.php?plugin_status=active", PHP_VERSION, "https://www.singleid.com/","5.3.3") . "</p></div>";
}

/**
 * Adds a notice to the admin interface that the WordPress multisite is not yet tested
 *
 */
function singleid_AddWpMultiError() {
	echo "<div id='sm-version-error' class='error fade'><p><strong>" . __('Multisite wordpress is not yet tested for SingleID plugin.', 'singleid-first-class-login') . "</strong><br /> Unfortunately this release of SingleID plugin is not yet tested for a multisite wordpress</p></div>";
}




