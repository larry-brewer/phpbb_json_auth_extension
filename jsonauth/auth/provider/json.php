<?php

namespace tbsoftware\jsonauth\auth\provider;

/**
 * 
 * Generic JSON plugin for PHPBB 3.1+
 * 
 * Copyright 2019, Larry Brewer
 * <lawrencejbrewerjr@gmail.com>
 * Modified from here: 
 *
 * Allows phpbb to outsource authentication to
 * any service which provides a JSON formatted
 * verification of the current session.
 * 
 * e.g. a failed authentication from the remote server looks like this:
 * {"authenticated": false}
 * and a successful authentication looks something like this:
 * {"username": "chr15m", "admin": false, "authenticated": true, "email": "chrism@mccormick.cx", "avatar": "/media/img/avatar.png"} 
 * 
 * Assumes sharing of cookies between the forum and the authenticating site.
 * 
 * PHPBB variables defined in the admin:
 * json_auth_url
 * json_auth_logout_url
 * json_auth_login_page
 * json_auth_shared_cookie
 * json_auth_cookie
 * 
 * Test 
 * Existing user
 * New User
 * Inactive User
 * Banned User
 * Sign up user rails
 * Admin User
 */

global $request;

class json extends \phpbb\auth\provider\base
{
    protected $config;
    protected $request;
    protected $db;

    /**
     * Database Authentication Constructor
     */
    public function __construct(\phpbb\config\config $config, \phpbb\request\request_interface $request, \phpbb\db\driver\driver_interface $db)
    {
        $this->config = $config;
        $this->request = $request;
        $this->db = $db;

        $this->request->enable_super_globals();

        $ch = curl_init($this->config['json_auth_url']);
        if (!$ch) {
            return "Couldn't connect to server at " . $this->config['json_auth_url'];
        }
    }

    private function pre_log( $data ) {
        echo '<pre>';
        echo $data;
        echo '</pre>';
    }

    public function autologin() 
    {
        if (!isset($_COOKIE[$this->config['json_auth_shared_cookie']]))
        {
            return array();
        }

        $json_user = $this->user_from_json_request();
        var_dump($json_user);
        $this->pre_log("Json user: " . $json_user['username']);
        // are they authenticated already on the remote server
        if (!empty($json_user['username']))
        {
            $sql = 'SELECT *
                FROM ' . USERS_TABLE . "
                WHERE username_clean = '" . $this->db->sql_escape(utf8_clean_string($json_user['username'])) . "'";
            $result = $this->db->sql_query($sql);
            $row = $this->db->sql_fetchrow($result);
            $this->db->sql_freeresult($result);
            
            $this->pre_log('after query: ' . $sql);
            // if this user exists in the database already then go ahead and return them
            if ($row)
            {
                return ($row['user_type'] == USER_INACTIVE || $row['user_type'] == USER_IGNORE) ? array() : $row;
            }
            else 
            {
                // make sure we have the right functions for creating a new user
                if (!function_exists('user_add') || !function_exists('group_user_add'))
                {
                    global $phpbb_root_path, $phpEx;
                    include($phpbb_root_path . 'includes/functions_user.' . $phpEx);
                }
                // create this user if they do not exist yet (but are authenticated on the remote server)
                $id = user_add($json_user);
                $sql = 'SELECT *
                        FROM ' . USERS_TABLE . "
                        WHERE username_clean = '" . $this->db->sql_escape(utf8_clean_string($json_user['username'])) . "'";
                $result = $this->db->sql_query($sql);
                $row = $this->db->sql_fetchrow($result);
                $this->db->sql_freeresult($result);
                // if they were created successfully, return the new user's data
                if ($row)
                {
                    return $row;
                }
            }   
        }
    }
    /**
     * {@inheritdoc}
     */
    public function login($username, $password)
    {
        $user_row = $this->autologin_json();
        // do not allow empty password
        if ($user_row['authenticated'])
        {
            // Successful login... set user_login_attempts to zero...
            return array(
                'status'             => LOGIN_SUCCESS,
                'error_msg'          => false,
                'user_row'           => $row,
            );
        }
        else
        {
            // Redirect the user to the login page of the application
            header("Location: " . $this->config['json_auth_login_page']);
        }
    }

    public function validate_session($user)
    {   
        if (!isset($_COOKIE[$this->config['json_auth_shared_cookie']]))
        {
            return false;
        }
        
        $json_user = $this->user_from_json_request();
        $this->pre_log('validate session: ' . ($json_user && $user['username'] === $json_user->username) ? true : false);
        
        

        return ($json_user && $user['username'] === $json_user['username']) ? true : false;
    }

    public function acp()
	{
		// these are fields in the config for this auth provider
		return array(
			'json_auth_url',
			'json_auth_shared_cookie',
			'json_auth_cookie',
            'json_auth_logout_url',
            'json_auth_login_page'
		);
    }
    
    public function get_acp_template($new_config)
	{
		return array(
			'BLOCK_VAR_NAME' => 'json',
			'BLOCK_VARS' => array(
				'json_auth_url' => array(
					'NAME' => 'json_auth_url',
					'SHORT_DESC' => 'JSON Auth URL',
					'EXPLAIN' => 'URL where the /auth/external/ JSON page of the remote authenticator is.<br/>That page should return e.g.:{"username": "xxxxxxx", "admin": false, "authenticated": true, "email": "xxxx@xxxxxxx.com", "avatar": "/media/img/xxxx.png"}',
					'VALUE' => $new_config['json_auth_url'],
                ),
                'json_auth_shared_cookie' => array(
					'NAME' => 'json_auth_shared_cookie',
					'SHORT_DESC' => 'Shared cookie name',
					'EXPLAIN' => 'Name of the cookie which is shared between the remote system and phpbb.',
					'VALUE' => $new_config['json_auth_shared_cookie'],
                ),
                'json_auth_cookie' => array(
					'NAME' => 'json_auth_cookie',
					'SHORT_DESC' => 'Remote cookie name',
					'EXPLAIN' => 'Name of the cookie on the remote system (can be the same as the shared cookie name).',
					'VALUE' => $new_config['json_auth_cookie'],
                ),
                'json_auth_logout_url' => array(
					'NAME' => 'json_auth_logout_url',
					'SHORT_DESC' => 'Location to ping to log the user out:',
					'EXPLAIN' => 'URL that we should access with the session cookie in order to log the user out.',
					'VALUE' => $new_config['json_auth_logout_url'],
                ),
                'json_auth_login_page' => array(
					'NAME' => 'json_auth_login_page',
					'SHORT_DESC' => 'Where to redirect the user to log in:',
					'EXPLAIN' => 'Page to send the user to in order to log in on the remote system.',
					'VALUE' => $new_config['json_auth_login_page'],
				)
			),
			'TEMPLATE_FILE'	=> '@tbsoftware_jsonauth/auth_provider_json.html',
			'TEMPLATE_VARS' => array(),
		);
    }
    
    private function user_from_json_request() {
        // if we can't connect return an error.
        $ch = curl_init($this->config['json_auth_url']);
        curl_setopt($ch, CURLOPT_HEADER, 0);
        curl_setopt($ch, CURLOPT_COOKIESESSION, TRUE);
        // TODO: Try cookie deleted
        curl_setopt($ch, CURLOPT_COOKIEJAR, tempnam("/tmp", "json_phpbb_cookie_"));
        
        $cookie_value = $_COOKIE[$this->config['json_auth_shared_cookie']];
        
        curl_setopt($ch, CURLOPT_COOKIE, $this->config['json_auth_cookie'] . "=" . $cookie_value);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, FALSE);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        
        curl_setopt($ch, CURLOPT_POST, 1);

        // For Debugging
        curl_setopt($ch, CURLINFO_HEADER_OUT, true);
        curl_setopt($ch, CURLOPT_VERBOSE, 1);

        $output = curl_exec($ch);

        // For Debugging
        // $info = curl_getinfo($ch);
        // var_dump($info);
        // $this->pre_log($_COOKIE[$this->config['json_auth_shared_cookie']]);

        curl_close($ch);
        
        $vals = json_decode($output);
        if ($vals && $vals->authenticated) 
        {
            // ONLY FOR DEBUGGING
            // $vals->username = 'user';
            var_dump($vals);
            $vals = $this->merge_json_with_db_user($vals);
        }
        else 
        {
            $vals = null;
        }
        // For Debugging
        // var_dump($_COOKIE);
        
        return $vals;
    }

    private function merge_json_with_db_user($json_data) {
        $username = $json_data->username;
        $email = $json_data->email;
        $admin = $json_data->admin;
        
        if ($admin)
        {
            $sql = 'SELECT user_permissions 
                    FROM ' . USERS_TABLE . '
                    WHERE user_type = 3 limit 1';
            $result = $this->db->sql_query($sql);
            $admin_per = $this->db->sql_fetchrow($result);
            $this->db->sql_freeresult($result);

            $permissions = $admin_per['user_permissions'];
            $permissions = "";
            $group = $this->get_group("ADMINISTRATORS");
            $user->data['session_admin'] = true;
        }
        else
        {
            $permissions = "";
            $group = $this->get_group("REGISTERED");
        }
        
        // generate user account data
        $row = array(
            'username'              => $username,
            'user_password'         => phpbb_hash(rand()),
            'user_email'            => $email,
            'group_id'              => (int) $group,
            'user_type'             => ($admin) ? USER_FOUNDER : USER_NORMAL,
            'user_permissions'      => $permissions,
        );

        return $row;
    }

    private function get_group($name) 
    {
        // first retrieve default group id
        $sql = 'SELECT group_id
                FROM ' . GROUPS_TABLE . "
                WHERE group_name = '" . $this->db->sql_escape($name) . "'
                        AND group_type = " . GROUP_SPECIAL;
        $result = $this->db->sql_query($sql);
        $row = $this->db->sql_fetchrow($result);
        $this->db->sql_freeresult($result);
        return $row['group_id'];
    }
}