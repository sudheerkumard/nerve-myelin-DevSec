<?php
// Fixture for engine/myelin_engine/rules/sast/php.yaml (opengrep --test). Not executed.
$id = $_GET['id'];
// ruleid: nervve.php.sql-injection
mysqli_query($conn, "SELECT * FROM users WHERE id = " . $id);
// ok: nervve.php.sql-injection
mysqli_query($conn, "SELECT * FROM users WHERE id = " . intval($id));

// ruleid: nervve.php.command-injection
system("ping -c 1 " . $_POST['host']);
// ok: nervve.php.command-injection
system("ping -c 1 " . escapeshellarg($_POST['host']));

// ruleid: nervve.php.code-injection
eval($_REQUEST['code']);

// ruleid: nervve.php.file-inclusion
include $_GET['page'];

// ruleid: nervve.php.xss
echo "<h1>Hello " . $_GET['name'] . "</h1>";
// ok: nervve.php.xss
echo "<h1>Hello " . htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8') . "</h1>";

// ruleid: nervve.php.ssrf
$ch = curl_init($_GET['url']);

// ruleid: nervve.php.weak-crypto
$hash = md5($password);
// ok: nervve.php.file-inclusion
$in = file_get_contents("php://input");
// ruleid: nervve.php.file-inclusion
$d = file_get_contents("/srv/" . $_GET["f"]);
