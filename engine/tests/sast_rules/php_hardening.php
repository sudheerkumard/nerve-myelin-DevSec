<?php
// Fixture for engine/myelin_engine/rules/sast/php_hardening.yaml (opengrep --test).
// ruleid: nervve.php.unsafe-deserialisation
$o = unserialize($_COOKIE['prefs']);
// ok: nervve.php.unsafe-deserialisation
$p = json_decode($_COOKIE['prefs'], true);
// ruleid: nervve.php.path-traversal
echo file_get_contents($_GET['file']);
// ruleid: nervve.php.path-traversal
readfile("/var/docs/" . $_GET['name']);
// ruleid: nervve.php.xxe
libxml_disable_entity_loader(false);
function makeResetToken() {
    // ruleid: nervve.php.weak-random-token
    return md5(uniqid());
}
// ruleid: nervve.php.loose-comparison-auth
if (md5($pass) == $stored) { login(); }
