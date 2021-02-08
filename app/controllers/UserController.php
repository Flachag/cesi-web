<?php


namespace app\controllers;


use app\helpers\Auth;
use app\models\User;
use Exception;
use Slim\Http\Request;
use Slim\Http\Response;

class UserController extends Controller{

    public function login(Request $request, Response $response, array $args): Response {
        $this->view->render($response, 'pages/login.twig');
        return $response;
    }

    public function postLogin(Request $request, Response $response, array $args): Response {
        try {
            if (Auth::check()) {
                throw new Exception("Impossible de se connecter, vous êtes déjà connecté.");
            }

            $login = filter_var($request->getParsedBodyParam('login'), FILTER_SANITIZE_STRING);
            $password = filter_var($request->getParsedBodyParam('password'), FILTER_SANITIZE_STRING);

            if (!Auth::attempt($login, $password)) throw new Exception("Identifiant ou mot de passe invalide.");

            $response = $response->withRedirect($this->router->pathFor('app.account'));
        } catch (Exception $e) {
            $this->flash->addMessage('error', $e->getMessage());
            $response = $response->withRedirect($this->router->pathFor('app.home'));
        }
        return $response;
    }

    public function register(Request $request, Response $response, array $args): Response {
        $this->render($response, 'templates/pages/register.twig');
        return $response;
    }

    public function postRegister(Request $request, Response $response, array $args): Response {
        try {
            $username = filter_var($request->getParsedBodyParam('username'), FILTER_SANITIZE_STRING);
            $password = filter_var($request->getParsedBodyParam('password'), FILTER_SANITIZE_STRING);
            $password_conf = filter_var($request->getParsedBodyParam('password_conf'), FILTER_SANITIZE_STRING);
            $email = filter_var($request->getParsedBodyParam('email'), FILTER_SANITIZE_STRING);
            $firstname = filter_var($request->getParsedBodyParam('firstname'), FILTER_SANITIZE_STRING);
            $lastname = filter_var($request->getParsedBodyParam('lastname'), FILTER_SANITIZE_STRING);
            $address = filter_var($request->getParsedBodyParam('address'), FILTER_SANITIZE_STRING);

            if (mb_strlen($username, 'utf8') < 3 || mb_strlen($username, 'utf8') > 35) throw new Exception("Votre pseudo doit contenir entre 3 et 35 caractères.");
            if (mb_strlen($lastname, 'utf8') < 1 || mb_strlen($lastname, 'utf8') > 50) throw new Exception("Votre nom doit contenir entre 2 et 50 caractères.");
            if (mb_strlen($firstname, 'utf8') < 1 || mb_strlen($firstname, 'utf8') > 50) throw new Exception("Votre prénom doit contenir entre 2 et 50 caractères.");
            if (mb_strlen($password, 'utf8') < 8) throw new Exception("Votre mot de passe doit contenir au moins 8 caractères.");
            if (User::where('username', '=', $username)->exists()) throw new Exception("Ce pseudo est déjà pris.");
            if (User::where('email', '=', $email)->exists()) throw new Exception("Cet email est déjà utilisée.");
            if ($password != $password_conf) throw new Exception("La confirmation du mot de passe n'est pas bonne.");

            $user = new User();
            $user->lastname = $lastname;
            $user->firstname = $firstname;
            $user->username = $username;
            $user->email = $email;
            $user->address = $address;
            $user->password = password_hash($password, PASSWORD_DEFAULT);
            $user->save();

            $this->flash->addMessage('success', "L'utilisateur a été ajouté");
            $response = $response->withRedirect($this->router->pathFor('login'));
        } catch (\Exception $e){
            $this->flash->addMessage('error', $e->getMessage());
            $response = $response->withRedirect($this->router->pathFor("register"));
        }
        return $response;
    }
}