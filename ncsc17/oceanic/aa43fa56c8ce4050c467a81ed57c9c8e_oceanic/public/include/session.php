<?php

include "./db.php";

class Session {

    function Session(){
        $this->time = time();
        $this->startSession();
    }
   
    function startSession(){
        session_start(); 
    }
   
    function putData($value,$ident) {
        $_SESSION['value'][$ident] = $value;
    }
   
    function getData($ident) {
        if (isset($_SESSION['value'][$ident])) {
            $resultat=$_SESSION['value'][$ident];
            return $resultat;
            
        } else return null; 
    }
   
    function unsetData($ident) {
        unset($_SESSION['value'][$ident]);
    }

}

$session = new Session();
