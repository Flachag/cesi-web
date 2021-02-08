<?php

use app\controllers\AppController;
use app\extensions\TwigMessages;
use Dotenv\Dotenv;
use Illuminate\Database\Capsule\Manager;
use Slim\App;
use Slim\Flash\Messages;
use Slim\Http\Environment;
use Slim\Http\Uri;
use Slim\Views\Twig;
use Slim\Views\TwigExtension;
use Twig\Extra\Intl\IntlExtension;

require_once(__DIR__ . '/../vendor/autoload.php');

session_start();
date_default_timezone_set('Europe/Paris');

$env = Dotenv::createImmutable(__DIR__ . '/../');
$env->load();
$env->required(['DB_HOST', 'DB_PORT', 'DB_NAME', 'DB_USER', 'DB_PASSWORD']);

$db = new Manager();
$db->addConnection([
    'driver' => 'mysql',
    'host' => $_ENV['DB_HOST'],
    'port' => $_ENV['DB_PORT'],
    'database' => $_ENV['DB_NAME'],
    'username' => $_ENV['DB_USER'],
    'password' => $_ENV['DB_PASSWORD'],
    'charset' => 'utf8',
    'collation' => 'utf8_unicode_ci'
]);
$db->setAsGlobal();
$db->bootEloquent();

$app = new App(['settings' => ['displayErrorDetails' => 1]]);

$container = $app->getContainer();
$container['flash'] = function () {
    return new Messages();
};
$container['view'] = function ($container) {
    $view = new Twig(__DIR__ . '/../templates', [
        'cache' => false
    ]);

    $view->addExtension(new TwigExtension($container->router, Uri::createFromEnvironment(new Environment($_SERVER))));
    $view->addExtension(new TwigMessages(new Messages()));
    $view->addExtension(new IntlExtension());
    return $view;
};

$app->get("/", AppController::class . ':home')->setName("app.home");

$app->run();