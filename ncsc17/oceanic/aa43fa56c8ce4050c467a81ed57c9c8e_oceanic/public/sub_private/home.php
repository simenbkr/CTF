<?php 
    $user_session = $session->getData("login");
    if (!$user_session) {
        $header->redirect('mHome');
    }
?>

<pre>
NCSC17{placeholder}
</pre>

<form action="?action=aLogout" method="post">
    <button class="btn btn-lg btn-primary btn-block" type="submit">Sign out</button>
</form>
