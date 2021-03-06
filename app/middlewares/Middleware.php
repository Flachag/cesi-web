<?php

namespace app\middlewares;

use Slim\Container;

/**
 * Class Middleware
 * @package app\middlewares
 */
abstract class Middleware {

    /**
     * Slim's Container
     * @var Container
     */
    protected $container;

    /**
     * Controller constructor.
     * @param $container
     */
    public function __construct(Container $container) {
        $this->container = $container;
    }
}