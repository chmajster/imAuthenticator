<?php
declare(strict_types=1);$services=require dirname(__DIR__).'/src/bootstrap.php';header('Content-Type: application/samlmetadata+xml; charset=utf-8');header('Cache-Control: public,max-age=3600');echo $services['saml']->metadata();
