<?php
$id = $_GET['id'];
mysqli_query($db, "SELECT * FROM users WHERE id = " . $_GET['id']);   // VULN NM-SAST-035
$stmt = $db->prepare("SELECT * FROM users WHERE id = ?");              // SAFE prepared statement
system("ping " . $_GET['host']);                                       // VULN NM-SAST-036
eval($_POST['code']);                                                  // VULN NM-SAST-037
include($_GET['page'] . ".php");                                       // VULN NM-SAST-038
include("header.php");                                                 // SAFE constant include
