<?php

use app\controllers\AdminController;
use app\controllers\AppController;
use app\controllers\UserController;
use app\extensions\TwigMessages;
use app\helpers\Auth;
use app\middlewares\AuthMiddleware;
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
$env->required(['DB_HOST', 'DB_PORT', 'DB_NAME', 'DB_USER', 'DB_PASSWORD', 'AWS_ENDPOINT', 'AWS_REGION', 'AWS_BUCKET', 'MAIL_HOST', 'MAIL_PORT', 'MAIL_USER', 'MAIL_PASSWORD']);

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

    $view->getEnvironment()->addGlobal('auth', [
        'check' => Auth::check(),
        'user' => Auth::user()
    ]);

    $view->addExtension(new TwigExtension($container->router, Uri::createFromEnvironment(new Environment($_SERVER))));
    $view->addExtension(new TwigMessages(new Messages()));
    $view->addExtension(new IntlExtension());
    return $view;
};

$app->get("/", AppController::class . ':home')->setName("app.home");
$app->get("/verify/{token}", UserController::class . ':verifyToken')->setName("app.verify");
$app->get("/register", UserController::class . ':register')->setName("app.register");
$app->get("/login", UserController::class . ':login')->setName("app.login");
$app->post("/login", UserController::class . ':postLogin')->setName("app.login.submit");
$app->post("/register", UserController::class . ':postRegister')->setName("app.register.submit");

$app->group('', function (App $app) {
    $app->get('/account', UserController::class . ':account')->setName('app.account');
    $app->post('/account', UserController::class . ':updateAccount')->setName('app.account.submit');
    $app->post('/account/password', UserController::class . ':updatePassword')->setName('app.account.password.submit');
    $app->post('/account/image', UserController::class . ':uploadImage')->setName('app.account.image.submit');
    $app->get('/logout', UserController::class . ':logout')->setName('app.logout');
})->add(new AuthMiddleware($container));

$app->group('/admin', function(App $app) {
    $this->get('/', AdminController::class . ':admin')->setName('app.admin');
    $this->get('/delete/{id}', AdminController::class .':deleteUser')->setName('app.admin.delete');
    $this->post('/update/{id:[0-9]+}', AdminController::class . ':postUpdateUser')->setName('app.admin.user.update.submit');
    $this->get('/update/{id:[0-9]+}', AdminController::class . ':UpdateUser')->setName('app.admin.user.update');
})->add(new AuthMiddleware($container));
$app->run();