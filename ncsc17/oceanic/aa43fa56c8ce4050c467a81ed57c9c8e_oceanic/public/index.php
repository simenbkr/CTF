<?php
error_reporting(0);

$menu   = $_GET['menu'];
$action = $_GET['action'];

include "include/session.php";
include "include/header.php";
include "include/menu.php";
include "include/action.php";

?>
<!DOCTYPE html>
<html lang="en">
    <head>
        <meta charset="utf-8">
        <meta http-equiv="X-UA-Compatible" content="IE=edge">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Oceanic Airlines</title>
        <link href="css/bootstrap.min.css" rel="stylesheet">
        <link href="css/style.css" rel="stylesheet">
    </head>
    <body>
        <div class="container">
            <img class="logo" src="img/logo.gif">
            Welcome to Oceanic, the world's best airline!

            <div class="content">
                <?php include "$menu_page_content"; ?>
            </div>
        </div>
    </body>
</html>
