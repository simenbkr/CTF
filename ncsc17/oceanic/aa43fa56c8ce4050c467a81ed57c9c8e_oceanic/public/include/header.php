<?php

class myHeader {
    
    function redirect($menu, $f) {
        $this->host= $_SERVER['HTTP_HOST'];
        $this->uri  = rtrim(dirname($_SERVER['PHP_SELF']), '/\\'); 
        header("Location: http://$this->host$this->uri/index.php?menu=$menu&f=".$f);
        exit;
    }

}

$header = new myHeader();
