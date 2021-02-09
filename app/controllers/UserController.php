<?php


namespace app\controllers;


use app\helpers\Auth;
use app\models\User;
use Exception;
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\SMTP;
use Slim\Http\Request;
use Slim\Http\Response;

class UserController extends Controller{


    public function verifyToken(Request $request, Response $response, array $args): Response {
        try {
            $token = filter_var($args['token'], FILTER_SANITIZE_STRING);
            $user = User::where('token', $token)->firstOrFail();
            $user->token = null;
            $user->save();
            $this->flash->addMessage('success', "Votre compte a été validé, vous pouvez désormais vous connecter");
            return $response = $response->withRedirect($this->router->pathFor('app.login'));
        } catch (Exception $e) {
            $this->flash->addMessage('error', $e->getMessage());
            $response = $response->withRedirect($this->router->pathFor("app.login"));
        }

        return $response;
    }

    public function updateAccount(Request $request, Response $response, array $args): Response {
        try {
            $firstname = filter_var($request->getParsedBodyParam('firstname'), FILTER_SANITIZE_STRING);
            $lastname = filter_var($request->getParsedBodyParam('lastname'), FILTER_SANITIZE_STRING);
            $email = filter_var($request->getParsedBodyParam('email'), FILTER_SANITIZE_EMAIL);
            $address = filter_var($request->getParsedBodyParam('address'), FILTER_SANITIZE_STRING);
            $user = Auth::user();

            if ($user->email != $email) {
                if (User::where('email', $email)->exists()) throw new Exception("Cet email est déjà utilisée.");
            }

            $user->lastname = $lastname;
            $user->firstname = $firstname;
            $user->address = $address;
            $user->email = $email;
            $user->save();

            $this->flash->addMessage('success', "Votre modification a été enregistrée");
            return $response = $response->withRedirect($this->router->pathFor('app.account'));
        } catch (Exception $e) {
            $this->flash->addMessage('error', $e->getMessage());
            $response = $response->withRedirect($this->router->pathFor("app.account"));
        }
        return $response;
    }

    public function updatePassword(Request $request, Response $response, array $args): Response {
        try {
            $password = filter_var($request->getParsedBodyParam('password'), FILTER_SANITIZE_STRING);
            $newpassword = filter_var($request->getParsedBodyParam('newpassword'), FILTER_SANITIZE_STRING);
            $newpassword_conf = filter_var($request->getParsedBodyParam('newpassword_conf'), FILTER_SANITIZE_STRING);
            if (mb_strlen($newpassword, 'utf8') < 8) throw new Exception("Votre nouveau mot de passe doit contenir au moins 8 caractères.");
            if ($newpassword != $newpassword_conf) throw new Exception("La confirmation du mot de passe n'est pas bonne.");
            if (!password_verify($password, Auth::user()->password)) throw new Exception("Le mot de passe actuel est incorrect.");

            $user = Auth::user();
            $user->password = password_hash($newpassword, PASSWORD_DEFAULT);
            $user->save();

            $this->flash->addMessage('success', "Votre mot de passe a été modifié.");
            $response = $response->withRedirect($this->router->pathFor('app.account'));
        } catch (Exception $e) {
            $this->flash->addMessage('error', $e->getMessage());
            $response = $response->withRedirect($this->router->pathFor("app.account"));
        }
        return $response;
    }

    public function logout(Request $request, Response $response, array $args): Response {
        Auth::logout();

        $this->flash->addMessage('success', 'Vous avez bien été déconnecté');
        return $response->withRedirect($this->router->pathFor('app.login'));
    }

    public function login(Request $request, Response $response, array $args): Response {
        $this->view->render($response, 'pages/login.twig');
        return $response;
    }

    public function account(Request $request, Response $response, array $args): Response {
        $this->view->render($response, 'pages/account.twig');
        return $response;
    }

    public function postLogin(Request $request, Response $response, array $args): Response {
        try {
            if (Auth::check()) {
                throw new Exception("Impossible de se connecter, vous êtes déjà connecté.");
            }

            $login = filter_var($request->getParsedBodyParam('login'), FILTER_SANITIZE_STRING);
            $password = filter_var($request->getParsedBodyParam('password'), FILTER_SANITIZE_STRING);

            if (!Auth::attempt($login, $password)) throw new Exception("Identifiant ou mot de passe invalide. Avez-vous activé votre compte?");

            $response = $response->withRedirect($this->router->pathFor('app.account'));
        } catch (Exception $e) {
            $this->flash->addMessage('error', $e->getMessage());
            $response = $response->withRedirect($this->router->pathFor('app.login'));
        }
        return $response;
    }

    public function register(Request $request, Response $response, array $args): Response {
        $this->view->render($response, 'pages/register.twig');
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
            $user->token = sha1($username . time());
            $user->email = $email;
            $user->address = $address;
            $user->password = password_hash($password, PASSWORD_DEFAULT);
            $user->save();

            $mail = new PHPMailer(true);

            try {
                //Server settings
                $mail->SMTPDebug = SMTP::DEBUG_SERVER;
                $mail->isSMTP();
                $mail->Host       = $_ENV['MAIL_HOST'];
                $mail->SMTPAuth   = true;
                $mail->Username   = $_ENV['MAIL_USER'];
                $mail->Password   = $_ENV['MAIL_PASSWORD'];
                $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
                $mail->Port       = $_ENV['MAIL_PORT'];

                $mail->setFrom('jules.sayer@apitech-solution.com', 'Jules Sayer');
                $mail->addAddress($email, $firstname . ' ' . $lastname);

                // Content
                $mail->isHTML(true);
                $mail->Subject = 'CESI - Votre inscription';
                $mail->Body    = '<b>MERCI</b> pour votre <i>inscription</i>. <a href="http://cesi-web.local/verify/'. $user->token . '">Cliquez ici pour valider votre inscription.</a>';
                $mail->AltBody = 'Utilisez un client mail qui accepte le HTML....';

                $mail->send();
            } catch (Exception $e) {

            }

            $this->flash->addMessage('success', "Inscription validée, vous pouvez vous connecter.");
            $response = $response->withRedirect($this->router->pathFor('app.login'));
        } catch (\Exception $e){
            $this->flash->addMessage('error', $e->getMessage());
            $response = $response->withRedirect($this->router->pathFor("app.register"));
        }
        return $response;
    }
}