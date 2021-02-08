<?php


namespace app\controllers;


use app\helpers\Auth;
use app\models\User;
use Slim\Http\Request;
use Slim\Http\Response;

class AdminController extends Controller{
    public function admin(Request $request, Response $response, array $args): Response {
        $admin = Auth::user();
        if($admin->level == 1) {
            $this->view->render($response, 'pages/admin/admin.twig');
        } else {
            $this->flash->addMessage('error', "Vous n'avez pas les droits pour effectuer cette action.");
            $response = $response->withRedirect($this->router->pathFor('app.home'));
        }
        return $response;
    }

    public function deleteUser(Request $request, Response $response, array $args): Response {
        try{
            $admin = Auth::user();
            if($admin->level == 1) {
                $user = User::where('id', $args['id'])->firstOrFail();
                $user->delete();

                $this->flash->addMessage('success', "L'utilisateur a bien été supprimé !");
            }
            $response = $response->withRedirect($this->router->pathFor('app.admin'));
        } catch (\Exception $e){
            $this->flash->addMessage('error', 'Nous n\'avons pas pu supprimer cet utilisateur.');
            $response = $response->withRedirect($this->router->pathFor('app.admin'));
        }
        return $response;
    }

    public function updateUser(Request $request, Response $response, array $args): Response{
        $admin = Auth::user();
        if($admin->level == 1) {
            $this->view->render($response, 'pages/admin/update.twig');
        } else {
            $this->flash->addMessage('error', "Vous n'avez pas les droits pour effectuer cette action.");
            $response = $response->withRedirect($this->router->pathFor('app.home'));
        }
        return $response;
    }

    public function postUpdateUser(Request $request, Response $response, array $args): Response{
        try {
            $username = filter_var($request->getParsedBodyParam('username'), FILTER_SANITIZE_STRING);
            $email = filter_var($request->getParsedBodyParam('email'), FILTER_SANITIZE_STRING);
            $firstname = filter_var($request->getParsedBodyParam('firstname'), FILTER_SANITIZE_STRING);
            $lastname = filter_var($request->getParsedBodyParam('lastname'), FILTER_SANITIZE_STRING);
            $address = filter_var($request->getParsedBodyParam('address'), FILTER_SANITIZE_STRING);

            $user = User::where('id',$args['id'])->firstOrFail();

            if (mb_strlen($username, 'utf8') < 3 || mb_strlen($username, 'utf8') > 35) throw new Exception("Votre pseudo doit contenir entre 3 et 35 caractères.");
            if (mb_strlen($lastname, 'utf8') < 1 || mb_strlen($lastname, 'utf8') > 50) throw new Exception("Votre nom doit contenir entre 2 et 50 caractères.");

            if($user->username != $username){
                if (User::where('username', $username)->exists()) throw new AuthException("Ce pseudo est déjà utilisé.");
            }

            if($user->email != $email){
                if (User::where('email', $email)->exists()) throw new AuthException("Cet email est déjà utilisée.");
            }

            $user->username = $username;
            $user->email = $email;
            $user->firstname = $firstname;
            $user->lastname = $lastname;
            $user->address = $address;
            $user->save();

            $this->flash->addMessage('success', "Votre modification a été enregistrée");
            $response = $response->withRedirect($this->router->pathFor('app.admin.user.update', ['id' => $args['id']]));
        } catch (\Exception $e){
            $this->flash->addMessage('error', $e->getMessage());
            $response = $response->withRedirect($this->router->pathFor("app.admin"));
        }
        return $response;
    }
}