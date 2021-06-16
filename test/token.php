<?php
require "/phpwww/tools/vendor/autoload.php";
use Brady\Token\JWT;

$jwt = new JWT("hello");
$token = $jwt->getToken(['userName'=>"wang","age"=>10]);
var_dump($token);

$payload = $jwt->validateToken($token);
var_dump($payload);