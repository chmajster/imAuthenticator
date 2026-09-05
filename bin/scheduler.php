#!/usr/bin/env php
<?php
declare(strict_types=1);
$services=require dirname(__DIR__).'/src/bootstrap.php';
try{$result=$services['scheduler']->runDue(100);fwrite(STDOUT,json_encode($result,JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE|JSON_THROW_ON_ERROR).PHP_EOL);exit(($result['failed']??0)>0?2:0);}catch(Throwable$e){fwrite(STDERR,'Scheduler failure: '.$e->getMessage().PHP_EOL);exit(1);}
