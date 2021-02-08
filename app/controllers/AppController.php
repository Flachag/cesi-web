<?php

namespace app\controllers;

use Exception;
use Slim\Http\Request;
use Slim\Http\Response;

final class AppController extends Controller {
    public function home(Request $request, Response $response, array $args): Response {
        $response = $response->withJson('Hello World');
        return $response;
    }
}