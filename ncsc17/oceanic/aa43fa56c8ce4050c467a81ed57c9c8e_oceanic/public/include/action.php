<?php

include "./include/db.php";

class Action
{

    function Action(){
        global $action;
        global $menu;

        if($action=="aLogout") {
            $this->Logout();
        }

        if($action=="aLogin") {
            $this->Login($_POST['username'],$_POST['password']);
        }
    }

    function Logout() {
        global $session;
        global $header;
        $session->putData(0,'login');
        $session->unsetData('user');
        $header->redirect('mHome');
    }

    function Login($user,$password) {
        global $db;
        global $header;
        global $session;
        $validation = $db->searchuser($user,$password);

        if ($validation) {
            $session->putData('1','login');
            $session->putData($user,'user');
            $header->redirect('mUser');
        } else {
            $session->putData('0','login');
            $session->unsetData('user');
            $session->putData('yes','error');
            $header->redirect('mHome');
        }
    }
}

$actionObj = new Action();
