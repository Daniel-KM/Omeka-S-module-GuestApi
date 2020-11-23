<?php declare(strict_types=1);
namespace GuestApi\Controller;

use Doctrine\ORM\EntityManager;
use Guest\Entity\GuestToken;
use Guest\Stdlib\PsrMessage;
use Laminas\Authentication\AuthenticationService;
use Laminas\Http\Response;
use Laminas\Session\Container as SessionContainer;
use Omeka\Api\Adapter\UserAdapter;
use Omeka\Api\Manager as ApiManager;
use Omeka\Api\Representation\SiteRepresentation;
use Omeka\Entity\SitePermission;
use Omeka\Entity\User;
use Omeka\Stdlib\Message;
use Omeka\Stdlib\Paginator;
use Omeka\View\Model\ApiJsonModel;

/**
 * Allow to manage "me" via api.
 */
class ApiController extends \Omeka\Controller\ApiController
{
    const STATUS_SUCCESS = 'success';
    const STATUS_FAIL = 'fail';
    const STATUS_ERROR = 'error';

    /**
     * @var AuthenticationService
     */
    protected $authenticationService;

    /**
     * @var AuthenticationService
     */
    protected $passwordAuthenticationService;

    /**
     * @var UserAdapter
     */
    protected $userAdapter;

    /**
     * @var EntityManager
     */
    protected $entityManager;

    /**
     * @var array
     */
    protected $config;

    /**
     * @param Paginator $paginator
     * @param ApiManager $api
     * @param AuthenticationService $authenticationService
     * @param AuthenticationService $passwordAuthenticationService
     * @param UserAdapter $userAdapter
     * @param EntityManager $entityManager
     * @param array $config
     */
    public function __construct(
        Paginator $paginator,
        ApiManager $api,
        AuthenticationService $authenticationService,
        AuthenticationService $passwordAuthenticationService,
        UserAdapter $userAdapter,
        EntityManager $entityManager,
        array $config
    ) {
        $this->paginator = $paginator;
        $this->api = $api;
        $this->authenticationService = $authenticationService;
        $this->passwordAuthenticationService = $passwordAuthenticationService;
        $this->userAdapter = $userAdapter;
        $this->entityManager = $entityManager;
        $this->config = $config;
    }

    public function get($id)
    {
        $user = $this->authenticationService->getIdentity();
        if (!$user) {
            return $this->returnError(
                $this->translate('Access forbidden.'), // @translate
                Response::STATUS_CODE_403
            );
        }
        $userRepr = $this->userAdapter->getRepresentation($user);
        $response = new \Omeka\Api\Response;
        $response->setTotalResults(1);
        $response->setContent($userRepr);
        return new ApiJsonModel($response, $this->getViewOptions());
    }

    public function getList()
    {
        return $this->returnError(
            $this->translate('Method Not Allowed'), // @translate
            Response::STATUS_CODE_405
        );
    }

    public function create($data, $fileData = [])
    {
        return $this->returnError(
            $this->translate('Method Not Allowed'), // @translate
            Response::STATUS_CODE_405
        );
    }

    public function update($id, $data)
    {
        $user = $this->authenticationService->getIdentity();
        if (!$user) {
            return $this->returnError(
                $this->translate('Access forbidden.'), // @translate
                Response::STATUS_CODE_403
            );
        }
        return $this->updatePatch($user, $data, true);
    }

    public function replaceList($data)
    {
        return $this->returnError(
            $this->translate('Method Not Allowed'), // @translate
            Response::STATUS_CODE_405
        );
    }

    public function patch($id, $data)
    {
        $user = $this->authenticationService->getIdentity();
        if (!$user) {
            return $this->returnError(
                $this->translate('Access forbidden.'), // @translate
                Response::STATUS_CODE_403
            );
        }
        return $this->updatePatch($user, $data, false);
    }

    public function patchList($data)
    {
        return $this->returnError(
            $this->translate('Method Not Allowed'), // @translate
            Response::STATUS_CODE_405
        );
    }

    public function delete($id)
    {
        return $this->returnError(
            $this->translate('Method Not Allowed'), // @translate
            Response::STATUS_CODE_405
        );
    }

    public function deleteList($data)
    {
        return $this->returnError(
            $this->translate('Method Not Allowed'), // @translate
            Response::STATUS_CODE_405
        );
    }

    public function head($id = null)
    {
        return $this->returnError(
            $this->translate('Method Not Allowed'), // @translate
            Response::STATUS_CODE_405
        );
    }

    public function options()
    {
        return $this->returnError(
            $this->translate('Method Not Allowed'), // @translate
            Response::STATUS_CODE_405
        );
    }

    public function notFoundAction()
    {
        return $this->returnError(
            $this->translate('Page not found'), // @translate
            Response::STATUS_CODE_404
        );
    }

    /**
     * Login via api.
     *
     * Here, it's not the true api, so there may be credentials that are not checked.
     * @todo Use the true api to login.
     *
     * @return \Omeka\View\Model\ApiJsonModel
     */
    public function loginAction()
    {
        $returnError = $this->checkCors();
        if ($returnError) {
            return $returnError;
        }

        $user = $this->loggedUser();
        if ($user) {
            return $this->returnError(
                $this->translate('User cannot login: already logged.') // @translate
            );
        }

        // Post may be empty because it is not the standard controller, so get
        // the request directly.
        /** @var \Laminas\Http\PhpEnvironment\Request $request */
        $request = $this->getRequest();
        $data = json_decode($request->getContent(), true);
        // Post is required, but query is allowed for compatibility purpose.
        if (empty($data)) {
            $data = $this->params()->fromPost() ?: $this->params()->fromQuery();
        }

        if (empty($data['email'])) {
            return $this->returnError(
                $this->translate('Email is required.') // @translate
            );
        }

        if (!filter_var($data['email'], FILTER_VALIDATE_EMAIL)) {
            return $this->returnError(
                $this->translate('Invalid email.') // @translate
            );
        }

        if (empty($data['password'])) {
            return $this->returnError(
                $this->translate('Password is required.') // @translate
            );
        }

        // Process authentication via entity manager.
        /** @var \Omeka\Entity\User $user */
        $user = $this->entityManager->getRepository(User::class)->findOneBy([
            'email' => $data['email'],
            'isActive' => true,
        ]);

        if (!$user) {
            return $this->returnError(
                $this->translate('Wrong email or password.') // @translate
            );
        }

        if (!$user->verifyPassword($data['password'])) {
            return $this->returnError(
                // Same message as above for security.
                $this->translate('Wrong email or password.') // @translate
            );
        }

        $role = $user->getRole();
        $loginRoles = $this->settings()->get('guestapi_login_roles', []);
        if (!in_array($role, $loginRoles)) {
            return $this->returnError(
                sprintf($this->translate('Role "%s" is not allowed to login via api.'), $role) // @translate
            );
        }

        // TODO Use chain storage.
        if ($this->settings()->get('guestapi_login_session')) {
            // Check password.
            $this->passwordAuthenticationService->getAdapter()
                ->setIdentity($data['email'])
                ->setCredential($data['password']);
            $result = $this->passwordAuthenticationService
                ->authenticate();
            if (!$result->isValid()) {
                return $this->returnError(
                    $this->translate('Wrong email or password.') // @translate
                );
            }
        } else {
            $this->passwordAuthenticationService->clearIdentity();
        }

        $eventManager = $this->getEventManager();
        $eventManager->trigger('user.login', $user);

        // Redirect if needed (without session token: it won't be readable).
        $redirect = $this->params()->fromQuery('redirect');
        if ($redirect) {
            return $this->redirect()->toUrl($redirect);
        }

        return $this->returnSessionToken($user);
    }

    public function logoutAction()
    {
        $returnError = $this->checkCors();
        if ($returnError) {
            return $returnError;
        }

        /** @var \Omeka\Entity\User $user */
        $user = $this->authenticationService->getIdentity();
        if (!$user) {
            $user = $this->passwordAuthenticationService->getIdentity();
            if (!$user) {
                return $this->returnError(
                    $this->translate('User not logged.') // @translate
                );
            }
        }

        $this->removeSessionTokens($user);

        // TODO Use authentication chain.
        // In all cases, the logout is done on all authentication services.
        $this->authenticationService->clearIdentity();
        $this->passwordAuthenticationService->clearIdentity();

        $sessionManager = SessionContainer::getDefaultManager();

        $eventManager = $this->getEventManager();
        $eventManager->trigger('user.logout');

        $sessionManager->destroy();

        $message = $this->translate('Successfully logout.'); // @translate
        $result = [
            'status' => self::STATUS_SUCCESS,
            'data' => null,
            'message' => $message,
        ];
        return new ApiJsonModel($result, $this->getViewOptions());
    }

    public function sessionTokenAction()
    {
        $returnError = $this->checkCors();
        if ($returnError) {
            return $returnError;
        }

        $user = $this->loggedUser();
        if (!$user) {
            return $this->returnError(
                $this->translate('Access forbidden.'), // @translate
                Response::STATUS_CODE_403
            );
        }
        return $this->returnSessionToken($user);
    }

    /**
     * @see \Guest\Controller\Site\GuestController::registerAction()
     *
     * @todo Replace registerAction() by create()?
     * @return \Laminas\Http\Response|\Laminas\View\Model\ViewModel
     */
    public function registerAction()
    {
        $returnError = $this->checkCors();
        if ($returnError) {
            return $returnError;
        }

        $settings = $this->settings();
        $apiOpenRegistration = $settings->get('guestapi_open');
        if ($apiOpenRegistration === 'closed') {
            return $this->returnError(
                $this->translate('Access forbidden.'), // @translate
                Response::STATUS_CODE_403
            );
        }

        if ($this->loggedUser()) {
            return $this->returnError(
                $this->translate('User cannot register: already logged.') // @translate
            );
        }

        // Unlike api post for creation, the registering creates the user and
        // sends an email with a token.

        // TODO Use validator from the user form?

        // Post may be empty because it is not the standard controller, so get
        // the request directly.
        /** @var \Laminas\Http\PhpEnvironment\Request $request */
        $request = $this->getRequest();
        $data = json_decode($request->getContent(), true) ?: [];
        // Post is required, but query is allowed for compatibility purpose.
        // And in some cases, a part is in query...
        $data += ($this->params()->fromPost() ?: []) + ($this->params()->fromQuery() ?: []);

        $site = null;
        $settings = $this->settings();
        if ($settings->get('guestapi_register_site')) {
            if (empty($data['site'])) {
                return $this->returnError(
                    $this->translate('A site is required to register.') // @translate
                );
            }

            $site = is_numeric($data['site']) ? ['id' => $data['site']] : ['slug' => $data['site']];
            try {
                $site = $this->api->read('sites', $site)->getContent();
            } catch (\Omeka\Api\Exception\NotFoundException $e) {
                $site = null;
            }
            if (empty($site)) {
                return $this->returnError(
                    $this->translate('The site doesn’t exist.') // @translate
                );
            }
        }

        if (!isset($data['email'])) {
            return $this->returnError(
                $this->translate('Email is required.') // @translate
            );
        }

        if (!filter_var($data['email'], FILTER_VALIDATE_EMAIL)) {
            return $this->returnError(
                $this->translate('Invalid email.') // @translate
            );
        }

        if (empty($data['username'])) {
            $data['username'] = $data['email'];
        }

        if (!isset($data['password'])) {
            $data['password'] = null;
        }

        $emailIsValid = $settings->get('guestapi_register_email_is_valid');

        $userInfo = [];
        $userInfo['o:email'] = $data['email'];
        $userInfo['o:name'] = $data['username'];
        // TODO Avoid to set the right to change role (fix core).
        $userInfo['o:role'] = \Guest\Permissions\Acl::ROLE_GUEST;
        $userInfo['o:is_active'] = false;

        $response = $this->api->create('users', $userInfo);
        if (!$response) {
            /** @var \Omeka\Entity\User $user */
            $user = $this->entityManager->getRepository(User::class)->findOneBy([
                'email' => $userInfo['o:email'],
            ]);
            if ($user) {
                /** @var \Guest\Entity\GuestToken $guestToken */
                $guestToken = $this->entityManager->getRepository(GuestToken::class)
                    ->findOneBy(['email' => $userInfo['o:email']], ['id' => 'DESC']);
                if (empty($guestToken) || $guestToken->isConfirmed()) {
                    return $this->returnError(
                        $this->translate('Already registered.') // @translate
                    );
                }

                // This is a second registration, but the token is not set, but
                // the option may have been updated.
                if ($guestToken && $emailIsValid) {
                    $guestToken->setConfirmed(true);
                    $this->entityManager->persist($guestToken);
                    $this->entityManager->flush();
                    return $this->returnError(
                        $this->translate('Already registered.') // @translate
                    );
                }

                $message = $this->settings()->get('guestapi_message_confirm_register')
                    ?: $this->translate('Thank you for registering. Please check your email for a confirmation message. Once you have confirmed your request, you will be able to log in.'); // @translate
                $result = [
                    'status' => self::STATUS_SUCCESS,
                    'data' => [
                        'user' => $this->userAdapter->getRepresentation($user),
                    ],
                    'message' => $message,
                ];
                return new ApiJsonModel($result, $this->getViewOptions());
            }

            return $this->returnError(
                $this->translate('Unknown error.'), // @translate
                Response::STATUS_CODE_500
            );
        }

        /** @var \Omeka\Entity\User $user */
        $user = $response->getContent()->getEntity();
        $user->setPassword($data['password']);
        $user->setRole(\Guest\Permissions\Acl::ROLE_GUEST);
        // The account is active, but not confirmed, so login is not possible.
        // Guest user has no right to set active his account.
        // Except if the option "email is valid" is set.
        $user->setIsActive(true);

        $id = $user->getId();
        if (!empty($data['user-settings'])) {
            $userSettings = $this->userSettings();
            foreach ($data['user-settings'] as $settingId => $settingValue) {
                $userSettings->set($settingId, $settingValue, $id);
            }
        }

        // Add the user as a viewer of the specified site.
        // TODO Add a check of the site.
        if ($site) {
            // A guest user cannot update site, so the entity manager is used.
            $siteEntity = $this->api->read('sites', $site->id(), [], ['responseContent' => 'resource'])->getContent();
            $sitePermission = new SitePermission;
            $sitePermission->setSite($siteEntity);
            $sitePermission->setUser($user);
            $sitePermission->setRole(SitePermission::ROLE_VIEWER);
            $siteEntity->getSitePermissions()->add($sitePermission);
            $this->entityManager->persist($siteEntity);
            $this->entityManager->flush();
        // $this->api->update('sites', $site->id(), [
            //     'o:site_permission' => [
            //         'o:user' => ['o:id' => $user->getId()],
            //         'o:role' => 'viewer',
            //     ],
            // ], [], ['isPartial' => true]);
        } else {
            $site = $this->defaultSite();
            // User is flushed when the guest user token is created.
            $this->entityManager->persist($user);
        }

        // Set the current site, disabled in api.
        $this->getPluginManager()->get('currentSite')->setSite($site);

        if ($emailIsValid) {
            $this->entityManager->flush();
            $guestToken = null;
        } else {
            $guestToken = $this->createGuestToken($user);
        }
        $message = $this->prepareMessage('register-email-api', [
            'user_name' => $user->getName(),
            'user_email' => $user->getEmail(),
            'token' => $guestToken,
            'site' => $site,
        ]);
        $messageText = $this->prepareMessage('register-email-api-text', [
            'user_name' => $user->getName(),
            'user_email' => $user->getEmail(),
            'token' => $guestToken,
            'site' => $site,
        ]);
        $fromEmail = $this->settings()->get('administrator_email');
        $fromName = $this->settings()->get('installation_title');
        $result = $this->sendEmail(
            $user->getEmail(),
            $message['subject'],
            $message['body'],
            $user->getName(),
            $messageText['body'],
            $fromEmail,
            $fromName
        );
        if (!$result) {
            return $this->returnError(
                $this->translate('An error occurred when the email was sent.'), // @translate
                Response::STATUS_CODE_500
            );
        }

        if ($emailIsValid) {
            $message = $this->settings()->get('guestapi_message_confirm_register')
                ?: $this->translate('Thank you for registering. You can now log in and use the library.'); // @translate
        } else {
            $message = $this->settings()->get('guestapi_message_confirm_register')
                ?: $this->translate('Thank you for registering. Please check your email for a confirmation message. Once you have confirmed your request, you will be able to log in.'); // @translate
        }

        $result = [
            'status' => self::STATUS_SUCCESS,
            'data' => [
                'user' => $this->userAdapter->getRepresentation($user),
            ],
            'message' => $message,
        ];
        return new ApiJsonModel($result, $this->getViewOptions());
    }

    /**
     * Check cors and prepare the response.
     *
     * @return \Omeka\View\Model\ApiJsonModel|null
     */
    protected function checkCors()
    {
        // Check cors if any.
        $cors = $this->settings()->get('guestapi_cors') ?: ['*'];
        if (in_array('*', $cors)) {
            $origin = '*';
        } else {
            /** @var \Laminas\Http\Header\Origin|false $origin */
            $origin = $this->getRequest()->getHeader('Origin');
            if ($origin) {
                $origin = $origin->getFieldValue();
            }
            if (!$origin
                || (!is_array($origin) && !in_array($origin, $cors))
                || (is_array($origin) && !array_intersect($origin, $cors))
            ) {
                return $this->returnError(
                    $this->translate('Access forbidden.'), // @translate
                    Response::STATUS_CODE_403
                );
            }
        }

        // Add cors origin.
        $session = json_decode(json_encode($_SESSION), true);
        $this->getResponse()->getHeaders()
            ->addHeaderLine('Access-Control-Allow-Origin', $origin)
            // @link https://stackoverflow.com/questions/58270663/samesite-warning-chrome-77
            ->addHeaderLine('Set-Cookie',
                session_name() . '='
                . ($session['__ZF']['_VALID']['Laminas\Session\Validator\Id'] ?? '')
                . '; Path=/; HttpOnly; Secure; SameSite=None')
        ;
        return null;
    }

    /**
     * Check if a user is logged.
     *
     * This method simplifies derivative modules that use the same code.
     *
     * @return bool
     */
    protected function isUserLogged()
    {
        return $this->authenticationService->hasIdentity();
    }

    /**
     * Check if a user is logged and return it.
     *
     * This method simplifies derivative modules that use the same code.
     *
     * @return User|null
     */
    protected function loggedUser()
    {
        $user = $this->authenticationService->getIdentity();
        if ($user && $this->settings()->get('guestapi_login_session')) {
            $userPass = $this->passwordAuthenticationService->getIdentity();
            if ($user !== $userPass) {
                $storage = $this->passwordAuthenticationService->getStorage();
                $storage->clear();
                $storage->write($user);
            }
        } else {
            $this->passwordAuthenticationService->clearIdentity();
        }
        return $user;
    }

    /**
     * Update me is always a patch.
     *
     * @param User $user
     * @param array $data
     * @param bool $isUpdate Currently not used: always a partial patch.
     * @return \Omeka\View\Model\ApiJsonModel
     */
    protected function updatePatch(User $user, array $data, $isUpdate = false)
    {
        if (empty($data) || !array_filter($data)) {
            return $this->returnError(
                $this->translate('Request is empty.'), // @translate
                Response::STATUS_CODE_400
            );
        }

        if (isset($data['password']) || isset($data['new_password'])) {
            return $this->changePassword($user, $data);
        }

        // By exception, two common metadata can be without prefix.
        if (isset($data['name'])) {
            $data['o:name'] = $data['name'];
        }
        unset($data['name']);
        if (isset($data['email'])) {
            $data['o:email'] = $data['email'];
        }
        unset($data['email']);

        if (isset($data['o:email'])) {
            $settings = $this->settings();
            if ($settings->get('guestapi_register_site')) {
                $site = $this->userSites($user, true);
                if (empty($site)) {
                    return $this->returnError(
                        $this->translate('Email cannot be updated: the user is not related to a site.'), // @translate
                        Response::STATUS_CODE_400
                    );
                }
            } else {
                $site = $this->defaultSite();
            }

            $this->getPluginManager()->get('currentSite')->setSite($site);
            return $this->changeEmail($user, $data);
        }

        // For security, keep only the updatable data.
        // TODO Check if acl forbids change of the role for guest and other public roles.
        $toPatch = array_intersect_key($data, [
            'o:name' => null,
            // 'o:email' => null,
            // 'password' => null,
            // 'new_password' => null,
        ]);
        if (count($data) !== count($toPatch)) {
            return $this->returnError(
                $this->translate('Your request contains metadata that cannot be updated.'), // @translate
                Response::STATUS_CODE_400
            );
        }

        if (isset($data['o:name']) && empty($data['o:name'])) {
            return $this->returnError(
                $this->translate('The new name is empty.'), // @translate
                Response::STATUS_CODE_400
            );
        }

        // Update me is always partial for security, else use standard api.
        $response = $this->api->update('users', $user->getId(), $toPatch, [], ['isPartial' => true]);
        return new ApiJsonModel($response, $this->getViewOptions());
    }

    protected function changePassword(User $user, array $data)
    {
        // TODO Remove limit to update password separately.
        if (count($data) > 2) {
            return $this->returnError(
                $this->translate('You cannot update password and another data in the same time.'), // @translate
                Response::STATUS_CODE_400
            );
        }
        if (empty($data['password'])) {
            return $this->returnError(
                $this->translate('Existing password empty.'), // @translate
                Response::STATUS_CODE_400
            );
        }
        if (empty($data['new_password'])) {
            return $this->returnError(
                $this->translate('New password empty.'), // @translate
                Response::STATUS_CODE_400
            );
        }
        if (strlen($data['new_password']) < 6) {
            return $this->returnError(
                $this->translate('New password should have 6 characters or more.'), // @translate
                Response::STATUS_CODE_400
            );
        }
        if (!$user->verifyPassword($data['password'])) {
            // Security to avoid batch hack.
            sleep(1);
            return $this->returnError(
                $this->translate('Wrong password.'), // @translate
                Response::STATUS_CODE_400
            );
        }

        $user->setPassword($data['new_password']);
        $this->entityManager->persist($user);
        $this->entityManager->flush();

        $message = $this->translate('Password successfully changed'); // @translate
        $result = [
            'status' => self::STATUS_SUCCESS,
            'data' => [
                'user' => $this->userAdapter->getRepresentation($user),
            ],
            'message' => $message,
        ];
        return new ApiJsonModel($result, $this->getViewOptions());
    }

    /**
     * Update email.
     *
     * @todo Factorize with Guest.
     *
     * @param User $user
     * @param array $data
     * @return \Omeka\View\Model\ApiJsonModel
     */
    protected function changeEmail(User $user, array $data)
    {
        // TODO Remove limit to update email separately.
        if (count($data) > 1) {
            return $this->returnError(
                $this->translate('You cannot update email and another data in the same time.'), // @translate
                Response::STATUS_CODE_400
            );
        }
        if (empty($data['o:email'])) {
            return $this->returnError(
                $this->translate('New email empty.'), // @translate
                Response::STATUS_CODE_400
            );
        }
        $email = $data['o:email'];
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            return $this->returnError(
                new Message($this->translate('"%1$s" is not an email.'), $email), // @translate
                Response::STATUS_CODE_400
            );
        }

        if ($email === $user->getEmail()) {
            return $this->returnError(
                new Message($this->translate('The new email is the same than the current one.')), // @translate
                Response::STATUS_CODE_400
            );
        }

        $existUser = $this->api()->searchOne('users', ['email' => $email])->getContent();
        if ($existUser) {
            // Avoid a hack of the database.
            sleep(1);
            return $this->returnError(
                new Message($this->translate('The email "%s" is not yours.'), $email), // @translate
                Response::STATUS_CODE_400
            );
        }

        $site = $this->currentSite();

        $guestToken = $this->createGuestToken($user);
        $message = $this->prepareMessage('update-email', [
            'user_email' => $email,
            'user_name' => $user->getName(),
            'token' => $guestToken,
        ], $site);
        $result = $this->sendEmail($email, $message['subject'], $message['body'], $user->getName());
        if (!$result) {
            $message = new Message($this->translate('An error occurred when the email was sent.')); // @translate
            $this->logger()->err('[GuestApi] ' . $message);
            return $this->returnError(
                $message,
                Response::STATUS_CODE_500
            );
        }

        $message = new Message($this->translate('Check your email "%s" to confirm the change.'), $email); // @translate
        $result = [
            'status' => self::STATUS_SUCCESS,
            'data' => [
                'user' => $this->userAdapter->getRepresentation($user),
            ],
            'message' => $message,
        ];
        return new ApiJsonModel($result, $this->getViewOptions());
    }

    protected function prepareSessionToken(User $user)
    {
        $this->removeSessionTokens($user);

        // Create a new session token.
        $key = new \Omeka\Entity\ApiKey;
        $key->setId();
        $key->setLabel('guestapi_session');
        $key->setOwner($user);
        $keyId = $key->getId();
        $keyCredential = $key->setCredential();
        $this->entityManager->persist($key);

        $this->entityManager->flush();

        return [
            'o:user' => [
                '@id' => $this->url()->fromRoute('api/default', ['resource' => 'users', 'id' => $user->getId()], ['force_canonical' => true]),
                'o:id' => $user->getId(),
            ],
            'key_identity' => $keyId,
            'key_credential' => $keyCredential,
        ];
    }

    protected function removeSessionTokens(User $user): void
    {
        // Remove all existing session tokens.
        $keys = $user->getKeys();
        foreach ($keys as $keyId => $key) {
            if ($key->getLabel() === 'guestapi_session') {
                $keys->remove($keyId);
            }
        }
        $this->entityManager->flush();
    }

    protected function returnSessionToken(User $user)
    {
        $sessionToken = $this->prepareSessionToken($user);
        return new ApiJsonModel(
            [
                'status' => self::STATUS_SUCCESS,
                'data' => [
                    'session_token' => $sessionToken ?: null,
                ],
            ],
            $this->getViewOptions()
        );
    }

    protected function returnError(
        $message,
        $statusCode = Response::STATUS_CODE_400,
        array $errors = null,
        array $data = null,
        $isFail = false
    ) {
        $response = $this->getResponse();
        $response->setStatusCode($statusCode);
        if ($isFail) {
            $result = [
                'status' => self::STATUS_FAIL,
                'message' => $message,
                'code' => $statusCode,
                'data' => $data,
            ];
        } else {
            $result = [
                'status' => self::STATUS_ERROR,
                'message' => $message,
                'code' => $statusCode,
            ];
            if (is_array($errors)) {
                $result['errors'] = $errors;
            }
            if (is_array($data)) {
                $result['data'] = $data;
            }
        }
        return new ApiJsonModel($result, $this->getViewOptions());
    }

    /**
     * Prepare the template.
     *
     * @param string $template In case of a token message, this is the action.
     * @param array $data
     * @param SiteRepresentation $site
     * @return array Filled subject and body as PsrMessage, from templates
     * formatted with moustache style.
     */
    protected function prepareMessage($template, array $data, SiteRepresentation $site = null)
    {
        $settings = $this->settings();
        $site = $site ?: $this->currentSite();
        if ((isset($data['token']) || $settings->get('guestapi_register_site')) && empty($site)) {
            throw new \Exception('Missing site.'); // @translate
        }
        $default = [
            'main_title' => $settings->get('installation_title', 'Omeka S'),
            'site_title' => $site->title(),
            'site_url' => $site->siteUrl(null, true),
            'user_name' => '',
            'user_email' => '',
            'token' => null,
        ];

        $data += $default;

        if (isset($data['token'])) {
            $actions = [
                'register-email-api' => 'confirm-email',
                'register-email-api-text' => 'confirm-email',
            ];
            $action = $actions[$template] ?? $template;
            $data['token'] = $data['token']->getToken();
            $urlOptions = ['force_canonical' => true];
            $urlOptions['query']['token'] = $data['token'];
            $data['token_url'] = $this->url()->fromRoute(
                'site/guest/anonymous',
                ['site-slug' => $site->slug(),  'action' => $action],
                $urlOptions
            );
        }

        switch ($template) {
            case 'confirm-email':
                $subject = 'Your request to join {main_title} / {site_title}'; // @translate
                $body = $settings->get('guest_message_confirm_email',
                    $this->getConfig()['guest']['config']['guest_message_confirm_email']);
                break;

            case 'update-email':
                $subject = 'Update email on {main_title} / {site_title}'; // @translate
                $body = $settings->get('guest_message_update_email',
                    $this->getConfig()['guest']['config']['guest_message_update_email']);
                break;

            case 'register-email-api':
                $subject = $settings->get('guestapi_message_confirm_registration_subject',
                    $this->getConfig()['guestapi']['config']['guestapi_message_confirm_registration_subject']);
                $body = $settings->get('guestapi_message_confirm_registration',
                    $this->getConfig()['guestapi']['config']['guestapi_message_confirm_registration']);
                break;

            case 'register-email-api-text':
                $subject = $settings->get('guestapi_message_confirm_registration_subject',
                    $this->getConfig()['guestapi']['config']['guestapi_message_confirm_registration_subject']);
                $body = $settings->get('guestapi_message_confirm_registration_text',
                    $this->getConfig()['guestapi']['config']['guestapi_message_confirm_registration_text']);
                break;

                // Allows to manage derivative modules.
            default:
                $subject = !empty($data['subject']) ? $data['subject'] : '[No subject]'; // @translate
                $body = !empty($data['body']) ? $data['body'] : '[No message]'; // @translate
                break;
        }

        unset($data['subject']);
        unset($data['body']);
        $subject = new PsrMessage($subject, $data);
        $body = new PsrMessage($body, $data);

        return [
            'subject' => $subject,
            'body' => $body,
        ];
    }

    /**
     * cf. module Next (DefaultSiteSlug).
     *
     * @return \Omeka\Api\Representation\SiteRepresentation
     */
    protected function defaultSite()
    {
        $defaultSiteId = $this->settings()->get('default_site');
        if ($defaultSiteId) {
            try {
                $response = $this->api->read('sites', ['id' => $defaultSiteId], ['responseContent' => 'resource']);
                return $response->getContent();
            } catch (\Omeka\Api\Exception\NotFoundException $e) {
            }
        }
        return $this->api()->searchOne('sites', ['sort_by' => 'id'])->getContent();
    }

    /**
     * @return array
     */
    protected function getConfig()
    {
        return $this->config;
    }
}
