<?php

class myDatabase {

    function myDatabase() {
        $this->connection = mysql_connect('127.0.0.1', 'oceanic', 'password') or die(mysql_error());
        mysql_select_db('oceanic', $this->connection) or die(mysql_error());
    }

    function searchuser($user,$password) {
        $u = mysql_real_escape_string($user);
        $p = mysql_real_escape_string($password);
        $pw = hash('md5', $p, true);
        $q = "SELECT * FROM user_accounts where email='$u' and password='$pw'";
        $result = mysql_query($q, $this->connection);
        $num_rows = mysql_num_rows($result);
        if ($num_rows!=0) {
            $output = mysql_fetch_assoc($result);
                return true;
            } else {
                return false;
            }
        }
    }

$db = new myDatabase();
