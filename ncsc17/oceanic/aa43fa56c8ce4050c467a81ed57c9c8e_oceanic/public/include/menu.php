<?php

switch ($menu) {
    case "mHome":
        $menu_page_content = "./sub_content/login.php";
        $header_title="Login";
        break 1;

    case "mLogin":
        $menu_page_content = "./sub_content/login.php";
        $header_title="Login";
        break 1;

    case "mUser":
    default:
        $menu_page_content = "./sub_private/home.php";
        $header_title="User";
        break 1;
}

