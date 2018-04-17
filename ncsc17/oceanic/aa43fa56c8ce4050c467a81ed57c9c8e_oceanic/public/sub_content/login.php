<?php
    $user_session = $session->getData("login");
    if ($user_session) {
        $header->redirect('mHome');
    }
    $user  = $session->getData("user");
    $error = $session->getData("error");
?>

<form action="?action=aLogin" method="post" id="loginform">
    <?php
        if ($error == "yes") {
            echo '<div class="alert alert-danger">Incorrect Login</div>';
        }
    ?>
    <input name="username" type="text" class="form-control" placeholder="Username" required autofocus value="<?php echo $user; ?>">
    <input name="password" type="password" id="password" value="" class="form-control" placeholder="Password" required>
    <button class="btn btn-lg btn-primary btn-block" type="submit">Sign in</button>
    
</form>

<?php
    $session->unsetData("login");
    $session->unsetData("error");
?>
