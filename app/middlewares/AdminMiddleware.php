<?php

namespace app\middlewares;

use app\helpers\Auth;
use Exception;
use Slim\Http\Request;
use Slim\Http\Response;

class AdminMiddleware extends Middleware {

    /**
     * @param Request $request
     * @param Response $response
     * @param $next
     * @return Response
     */
    public function __invoke(Request $request, Response $response, $next): Response {
        try {
            if (!Auth::check() || Auth::user()->role != 1) throw new Exception();
        } catch (Exception $e) {
            $this->container->flash->addMessage('error', 'Vous n\'avez pas les droits de visiter cette page.');
            return $response->withRedirect($this->container->router->pathFor('app.login'));
        }

        $response = $next($request, $response);
        return $response;
    }
}