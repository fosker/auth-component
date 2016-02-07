<?php

namespace Auth;

/**
 * use models\User;
 * use models\Role;
 * use models\Auth;
 * use models\UserProviders;
 */

use Auth\AuthException;
use Acl\Acl;
use Auth\Session;


class Auth
{
    private $session;

    public function __construct()
    {
        $this->session = Session::getSession();
    }

    /**
     * @param $controller
     * @param $action
     * @return bool
     * @throws \Acl\AclException
     */
    public function auth($controller, $action)
    {
        $acl = new Acl();
        $user = new User();

        if($this->session->token) {
            $user_id = A::find(['token' => $this->session->token])[0]->user_id;
            if(!$user_id) {
                $this->reset();
                $user->role_id = 3;
            } else
                $user = User::find(['id' => $user_id])[0];
        } else
            $user->role_id = 3;

        $role = Role::find(['id' => $user->role_id])[0]->name;

        if($acl->isAllowed($role, $controller, $action))
            return true;
        else return false;
    }

    /**
     * @param User $u
     * @return bool
     * @throws \Auth\AuthException
     */
    public function loginPass(User $u)
    {
        if(!$this->session->token) {
            $user = User::find(['login' => $u->login])[0];
            $auth = new A();
            if ($user) {
                if(password_verify($u->password, $user->password)) {
                    $auth->via_password = true;
                    $auth->user_id = $user->id;
                    $auth->token = uniqid();
                    $auth->save();

                    $this->session->token = $auth->token;
                    $this->session->user = $user;

                    return true;
                }
            } else
                throw new AuthException('Wrong login or password');
        } else
            throw new AuthException('You are already logged in!');
    }

    /**
     * @return bool
     * @throws \Auth\AuthException
     */
    public function loginSocial()
    {
        if(!$this->session->token) {
            if (isset($_POST['token']) && isset($_SERVER['HTTP_HOST'])) {
                $s = file_get_contents('http://ulogin.ru/token.php?token=' . $_POST['token'] . '&host=' . $_SERVER['HTTP_HOST']);
                $result = json_decode($s, true);

                $userProviders = UserProviders::find(['uid' => $result['uid']])[0];

                $auth = new A();
                $auth->user_id = $userProviders->user_id;
                $auth->provider_id = $userProviders->provider_id;
                $auth->token = uniqid();
                $auth->save();

                $this->session->token = $auth->token;
                $this->session->user = User::find(['id' => $auth->user_id])[0];

                return true;
            }
        } else
            throw new AuthException('You are already logged in!');
    }

    /**
     * @return bool
     */
    public function logout()
    {
        $this->reset();
        return $this->session->destroy();
    }

    private function reset()
    {
        unset($this->session->user);
        unset($this->session->token);
    }
}