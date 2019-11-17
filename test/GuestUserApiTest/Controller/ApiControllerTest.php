<?php

namespace GuestUserApiTest\Controller;

use Zend\Form\Element\Csrf;
use GuestUser\Entity\GuestUserToken;

class ApiControllerTest extends GuestUserControllerTestCase
{
    protected $guestUser;

    public function tearDown()
    {
        $this->loginAsAdmin();
        $this->deleteGuestUser();
        parent::tearDown();
    }

    /**
     * @test
     */
    public function registerShouldDisplayLogin()
    {
        $this->postDispatch('/s/test/guest/register', [
            'user-information' => [
                'o:email' => 'test3@test.fr',
                'o:name' => 'test',
            ],
            'change-password' => [
                'password' => 'foobar',
                'password-confirm' => 'foobar',
            ],
            'csrf' => (new Csrf('csrf'))->getValue(),
        ]);

        $this->assertXPathQueryContentContains('//li[@class="success"]', 'Thank you for registering. Please check your email for a confirmation message. Once you have confirmed your request, you will be able to log in.');
        $readResponse = $this->api()->read('sites', [
            'slug' => 'test',
        ]);
        $siteRepresentation = $readResponse->getContent();

        $mailer = $this->getServiceLocator()->get('Omeka\Mailer');
        $body = $mailer->getMessage()->getBody();
        $link = '<a href=\''.$siteRepresentation->siteUrl().'/guest/confirm?token='.$this->getUserToken('test3@test.fr')->getToken().'\'>';
        $this->assertContains('You have registered for an account on '.$link.'Test</a>. Please confirm your registration by following '.$link.'this link</a>.  If you did not request to join Test please disregard this email.', $body);
    }

    /**
     * @test
     */
    public function tokenlinkShouldValidateGuestUser()
    {
        $user = $this->createGuestUser();
        $userToken = $this->getUserToken($user->email());
        $this->dispatch('/s/test/guest/confirm?token='.$userToken->getToken());
        $this->assertTrue($userToken->isConfirmed());
        $this->assertRedirect('guest/login');
        $this->assertXPathQueryContentContains('//li[@class="success"]', 'Thanks for joining Test! You can now log using the password you chose.');
    }

    /**
     * @test
     */
    public function wrongTokenlinkShouldNotValidateGuestUser()
    {
        $user = $this->createGuestUser();
        $this->dispatch('/s/test/guest/confirm?token=1234');

        $this->assertFalse($this->getUserToken($user->email())->isConfirmed());
    }

    /**
     * @test
     */
    public function updateAccountWithNoPassword()
    {
        $user = $this->createGuestUser();
        $em = $this->getEntityManager();
        $this->getUserToken($user->email())->setConfirmed(true);
        $em->flush();
        $this->login('guest@test.fr', 'test');

        $this->postDispatch('/s/test/guest/update-account', [
            'user-information' => [
                'o:email' => 'test4@test.fr',
                'o:name' => 'test2',
            ],
            'csrf' => (new Csrf('csrf'))->getValue(),
        ]);

        $this->assertNotNull($em->getRepository('Omeka\Entity\User')->findOneBy(['email' => 'test4@test.fr', 'name' => 'test2']));
    }

    /**
     * @test
     */
    public function deleteUnconfirmedUserShouldRemoveToken()
    {
        $user = $this->createGuestUser();
        $userId = $user->id();
        $em = $this->getEntityManager();

        $this->deleteGuestUser();

        $userToken = $em->getRepository(GuestUserToken::class)
            ->findOneBy(['user' => $userId]);
        $this->assertNull($userToken);
    }

    /**
     * @test
     */
    public function registerNeedsValidation()
    {
        // This avoids warning:
        // session_destroy(): Session object destruction failed
        session_write_close();
        session_start();

        $user = $this->createGuestUser();
        $this->logout();

        $csrf = new Csrf('loginform_csrf');
        $this->postDispatch('/s/test/guest/login', [
            'email' => 'guest@test.fr',
            'password' => 'test',
            'loginform_csrf' => $csrf->getValue(),
            'submit' => 'Log+in',
        ]);

        $this->assertXPathQueryContentContains('//li[@class="error"]', 'Your account has not been activated');
    }

    /**
     * @test
     */
    public function loginShouldDisplayWrongEmailOrPassword()
    {
        // This avoids warning:
        // session_destroy(): Session object destruction failed
        session_write_close();
        session_start();

        $this->logout();
        $this->postDispatch('/s/test/guest/login', [
            'email' => 'test@test.fr',
            'password' => 'test2',
            'csrf' => (new Csrf('csrf'))->getValue(),
            'submit' => 'Log+in',
        ]);

        $this->assertXPathQueryContentContains('//li[@class="error"]', 'Email or Password invalid');
    }

    /**
     * @test
     */
    public function logoutShouldLogoutUser()
    {
        $this->createGuestUser();
        $this->login('guest@test.fr', 'test');
        $this->dispatch('/s/test/guest/logout');
        $auth = $this->getServiceLocator()->get('Omeka\AuthenticationService');
        $this->assertFalse($auth->hasIdentity());
    }

    /**
     * @test
     */
    public function loginOkShouldRedirect()
    {
        $this->postDispatch('/s/test/guest/login', [
            'email' => 'test@test.fr',
            'password' => 'test',
            'csrf' => (new Csrf('csrf'))->getValue(),
            'submit' => 'Log+in',
        ]);

        $this->assertRedirect('/s/test');
    }

    protected function createGuestUser()
    {
        $em = $this->getEntityManager();

        $email = 'guest@test.fr';
        $response = $this->api()->create('users', [
            'o:email' => $email,
            'o:name' => 'guest',
            'o:role' => 'guest',
            'o:is_active' => true,
        ]);
        $user = $response->getContent();
        $userEntity = $user->getEntity();
        $userEntity->setPassword('test');

        $guest = new GuestUserToken;
        $guest->setEmail($email);
        $guest->setUser($userEntity);
        $guest->setToken(sha1('tOkenS@1t' . microtime()));

        $em->persist($userEntity);
        $em->flush();
        $em->persist($guest);
        $em->flush();

        $this->guestUser = $user;

        return $user;
    }

    protected function deleteGuestUser()
    {
        if (isset($this->guestUser)) {
            $this->api()->delete('users', $this->guestUser->id());
            $this->guestUser = null;
        }
    }

    protected function getUserToken($email)
    {
        $em = $this->getEntityManager();
        $repository = $em->getRepository(GuestUserToken::class);
        if ($users = $repository->findBy(['email' => $email])) {
            return array_shift($users);
        }

        return false;
    }
}
