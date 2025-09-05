<?php

use Ittmann\TokenVerify\TokenValidator;

chdir(realpath(dirname(__DIR__)));

require 'vendor/autoload.php';

$dotenv = Dotenv\Dotenv::createImmutable(getcwd());
$dotenv->load();

(new TokenValidator())->processRequest();
