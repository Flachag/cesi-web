<?php

namespace app\controllers;

use Exception;
use Slim\Http\Request;
use Slim\Http\Response;

final class AppController extends Controller {
    public function home(Request $request, Response $response, array $args): Response {
        $this->view->render($response, 'pages/index.twig');
        return $response;
    }
}