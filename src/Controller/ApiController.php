<?php
namespace GuestUserApi\Controller;

use Doctrine\ORM\EntityManager;
use GuestUser\Entity\GuestUserToken;
use GuestUser\Stdlib\PsrMessage;
use Omeka\Api\Representation\SiteRepresentation;
use Omeka\Entity\User;
use Omeka\Entity\SitePermission;
use Omeka\Mvc\Exception;
use Omeka\Stdlib\Message;
use Omeka\View\Model\ApiJsonModel;
use Zend\Authentication\AuthenticationService;
use Zend\Http\Response;
use Zend\Mvc\Controller\AbstractRestfulController;
use Zend\Mvc\MvcEvent;
use Zend\Stdlib\RequestInterface as Request;

/**
 * Allow to register via api.
 */
class ApiController extends AbstractRestfulController
{
    /**
     * @var AuthenticationService
     */
    protected $authenticationService;

    /**
     * @var EntityManager
     */
    protected $entityManager;

    /**
     * @var array
     */
    protected $config;

    /**
     * @var array
     */
    protected $viewOptions = [];

    protected $defaultRoles = [
        \Omeka\Permissions\Acl::ROLE_RESEARCHER,
        \Omeka\Permissions\Acl::ROLE_AUTHOR,
        \Omeka\Permissions\Acl::ROLE_REVIEWER,
        \Omeka\Permissions\Acl::ROLE_EDITOR,
        \Omeka\Permissions\Acl::ROLE_SITE_ADMIN,
        \Omeka\Permissions\Acl::ROLE_GLOBAL_ADMIN,
    ];

    /**
     * @param AuthenticationService $authenticationService
     * @param EntityManager $entityManager
     * @param array $config
     */
    public function __construct(
        AuthenticationService $authenticationService,
        EntityManager $entityManager,
        array $config
    ) {
        $this->authenticationService = $authenticationService;
        $this->entityManager = $entityManager;
        $this->config = $config;
    }

    public function create($data)
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

    public function get($id)
    {
        $user = $this->checkUserAndRole($id);
        if (!$user) {
            return $this->returnError(
                $this->translate('Access forbidden.'), // @translate
                Response::STATUS_CODE_403
            );
        }

        $response = $this->api()->read('users', $user->getId());
        return new ApiJsonModel($response, $this->getViewOptions());
    }

    public function getList()
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

    public function patch($id, $data)
    {
        $user = $this->checkUserAndRole($id);
        if (!$user) {
            return $this->returnError(
                $this->translate('Access forbidden.'), // @translate
                Response::STATUS_CODE_403
            );
        }

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
            // TODO Currently, the site is required to change the email.
            $site = $this->userSites($user, true);
            if (empty($site)) {
                return $this->returnError(
                    $this->translate('Email cannot be updated: the user is not related to a site.'), // @translate
                    Response::STATUS_CODE_400
                );
            }
            $site = $this->api()->read('sites', $site->getId())->getContent();
            $this->getPluginManager()->get('currentSite')->setSite($site);
            return $this->changeEmail($user, $data);
        }

        // For security, keep only the updatable data.
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

        $response = $this->api()->update('users', $user->getId(), $toPatch, [], ['isPartial' => true]);
        return new ApiJsonModel($response, $this->getViewOptions());
    }

    public function replaceList($data)
    {
        return $this->returnError(
            $this->translate('Method Not Allowed'), // @translate
            Response::STATUS_CODE_405
        );
    }

    public function patchList($data)
    {
        return $this->returnError(
            $this->translate('Method Not Allowed'), // @translate
            Response::STATUS_CODE_405
        );
    }

    public function update($id, $data)
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
     * @see \GuestUser\Controller\Site\GuestUserController::registerAction()
     *
     * @todo Replace registerAction() by create()?
     * @return \Zend\Http\Response|\Zend\View\Model\ViewModel
     */
    public function registerAction()
    {
        if ($this->isUserLogged()) {
            return $this->returnError(
                $this->translate('User cannot register: already logged.') // @translate
            );
        }

        // Here, it's not the true api, so there may be credentials that are not checked.
        // TODO Use the true api to register.

        if (!$this->getRequest()->isPost()) {
            return $this->returnError(
                $this->translate('Register requires a post.') // @translate
            );
        }

        // TODO Use validator from the user form?
        // TODO Remove this fix used to use post/query for /api/register and /guest-user/register.
        $data = $this->params()->fromQuery();
        if (empty($data)) {
            $data = $this->params()->fromPost();
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

        $site = null;
        $settings = $this->settings();
        if ($settings->get('guestuserapi_register_site')) {
            if (empty($data['site'])) {
                return $this->returnError(
                    $this->translate('A site is required to register.') // @translate
                );
            }

            $site = is_numeric($data['site']) ? ['id' => $data['site']] : ['slug' => $data['site']];
            try {
                $site = $this->api()->read('sites', $site)->getContent();
            } catch (\Omeka\Api\Exception\NotFoundException $e) {
                $site = null;
            }
            if (empty($site)) {
                return $this->returnError(
                    $this->translate('The site doesn’t exist.') // @translate
                );
            }
        }

        $emailIsValid = $this->settings()->get('guestuserapi_register_email_is_valid');

        $userInfo = [];
        $userInfo['o:email'] = $data['email'];
        $userInfo['o:name'] = $data['username'];
        // TODO Avoid to set the right to change role (fix core).
        $userInfo['o:role'] = \GuestUser\Permissions\Acl::ROLE_GUEST;
        $userInfo['o:is_active'] = false;

        $response = $this->api()->create('users', $userInfo);
        if (!$response) {
            /** @var \Omeka\Entity\User $user */
            $entityManager = $this->getEntityManager();
            $user = $entityManager->getRepository(User::class)->findOneBy([
                'email' => $userInfo['o:email'],
            ]);
            if ($user) {
                /** @var \GuestUser\Entity\GuestUserToken $guestUserToken */
                $guestUserToken = $entityManager->getRepository(GuestUserToken::class)
                    ->findOneBy(['email' => $userInfo['o:email']], ['id' => 'DESC']);
                if (empty($guestUserToken) || $guestUserToken->isConfirmed()) {
                    return $this->returnError(
                        $this->translate('Already registered.') // @translate
                    );
                }

                // This is a second registration, but the token is not set, but
                // the option may have been updated.
                if ($guestUserToken && $emailIsValid) {
                    $guestUserToken->setConfirmed(true);
                    $this->getEntityManager()->persist($guestUserToken);
                    $this->getEntityManager()->flush();
                    return $this->returnError(
                        $this->translate('Already registered.') // @translate
                    );
                }

                $message = $this->settings()->get('guestuserapi_message_confirm_register')
                    ?: $this->translate('Thank you for registering. Please check your email for a confirmation message. Once you have confirmed your request, you will be able to log in.'); // @translate
                $result = [
                    'status' => Response::STATUS_CODE_200,
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
        $user->setRole(\GuestUser\Permissions\Acl::ROLE_GUEST);
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
            $siteEntity = $this->api()->read('sites', $site->id(), [], ['responseContent' => 'resource'])->getContent();
            $sitePermission = new SitePermission;
            $sitePermission->setSite($siteEntity);
            $sitePermission->setUser($user);
            $sitePermission->setRole(SitePermission::ROLE_VIEWER);
            $siteEntity->getSitePermissions()->add($sitePermission);
            $this->getEntityManager()->persist($siteEntity);
            $this->getEntityManager()->flush();
            // $this->api()->update('sites', $site->id(), [
            //     'o:site_permission' => [
            //         'o:user' => ['o:id' => $user->getId()],
            //         'o:role' => 'viewer',
            //     ],
            // ], [], ['isPartial' => true]);
        } else {
            $siteId = $this->settings()->get('default_site');
            if ($siteId) {
                $site = $this->getEntityManager()
                    ->getRepository(\Omeka\Entity\Site::class)
                    ->find(['id' => $siteId]);
            } else {
                $site = $this->getEntityManager()
                    ->getRepository(\Omeka\Entity\Site::class)
                    ->findBy([], ['id' => 'asc'], 1);
                if ($site) {
                    $site = reset($site);
                }
            }
            // User is flushed when the guest user token is created.
            $this->getEntityManager()->persist($user);
        }

        // Set the current site, disabled in api.
        $this->getPluginManager()->get('currentSite')->setSite($site);

        if ($emailIsValid) {
            $this->getEntityManager()->flush();
            $guestUserToken = null;
        } else {
            $guestUserToken = $this->createGuestUserToken($user);
        }
        $message = $this->prepareMessage('register-email-api', [
            'user_name' => $user->getName(),
            'user_email' => $user->getEmail(),
            'token' => $guestUserToken,
            'site' => $site,
        ]);
        $messageText = $this->prepareMessage('register-email-api-text', [
            'user_name' => $user->getName(),
            'user_email' => $user->getEmail(),
            'token' => $guestUserToken,
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
            $message = $this->settings()->get('guestuserapi_message_confirm_register')
                ?: $this->translate('Thank you for registering. You can now log in and use the library.'); // @translate
        } else {
            $message = $this->settings()->get('guestuserapi_message_confirm_register')
                ?: $this->translate('Thank you for registering. Please check your email for a confirmation message. Once you have confirmed your request, you will be able to log in.'); // @translate
        }
        $result = [
            'status' => Response::STATUS_CODE_200,
            'message' => $message,
        ];
        return new ApiJsonModel($result, $this->getViewOptions());
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
        return $this->getAuthenticationService()->hasIdentity();
    }

    /**
     * This api is only for guest user, so some checks are done.
     *
     * @param string $id
     * @return \Omeka\Entity\User|null
     */
    protected function checkUserAndRole($id)
    {
        if ($id !== 'me') {
            return null;
        }

        // Access rights are managed automatically: only logged guest users can
        // update their account.
        // The check of the role is only a security, rights are set in Module.
        /** @var \Omeka\Entity\User $user */
        $user = $this->identity();
        if (!$user || $user->getRole() !== \GuestUser\Permissions\Acl::ROLE_GUEST) {
            return null;
        }

        return $user;
    }

    protected function changePassword(User $user, array $data)
    {
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
        $entityManager = $this->getEntityManager();
        $entityManager->persist($user);
        $entityManager->flush();

        $result = [
            'status' => Response::STATUS_CODE_200,
            'message' => $this->translate('Password successfully changed'), // @translate
        ];
        return new ApiJsonModel($result, $this->getViewOptions());
    }

    /**
     * Update email.
     *
     * @todo Factorize with GuestUser.
     *
     * @param User $user
     * @param array $data
     * @return \Omeka\View\Model\ApiJsonModel
     */
    protected function changeEmail(User $user, array $data)
    {
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

        $guestUserToken = $this->createGuestUserToken($user);
        $message = $this->prepareMessage('update-email', [
            'user_email' => $email,
            'user_name' => $user->getName(),
            'token' => $guestUserToken,
        ], $site);
        $result = $this->sendEmail($email, $message['subject'], $message['body'], $user->getName());
        if (!$result) {
            $message = new Message($this->translate('An error occurred when the email was sent.')); // @translate
            $this->logger()->err('[GuestUserApi] ' . $message);
            return $this->returnError(
                $message,
                Response::STATUS_CODE_500
            );
        }

        $message = new Message($this->translate('Check your email "%s" to confirm the change.'), $email); // @translate
        $result = [
            'status' => Response::STATUS_CODE_200,
            'message' => $message,
        ];
        return new ApiJsonModel($result, $this->getViewOptions());
    }

    protected function returnError($message, $statusCode = Response::STATUS_CODE_400, array $errors = null)
    {
        $response = $this->getResponse();
        $response->setStatusCode($statusCode);
        $result = [
            'status' => $statusCode,
            'message' => $message,
        ];
        if (is_array($errors)) {
            $result['errors'] = $errors;
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
        if ((isset($data['token']) || $settings->get('guestuserapi_register_site')) && empty($site)) {
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
            $data['token'] = $data['token']->getToken();
            $urlOptions = ['force_canonical' => true];
            $urlOptions['query']['token'] = $data['token'];
            $data['token_url'] = $this->url()->fromRoute(
                'site/guest-user',
                ['site-slug' => $site->slug(),  'action' => $template],
                $urlOptions
            );
        }

        switch ($template) {
            case 'confirm-email':
                $subject = 'Your request to join {main_title} / {site_title}'; // @translate
                $body = $settings->get('guestuser_message_confirm_email',
                    $this->getConfig()['guestuser']['config']['guestuser_message_confirm_email']);
                break;

            case 'update-email':
                $subject = 'Update email on {main_title} / {site_title}'; // @translate
                $body = $settings->get('guestuser_message_update_email',
                    $this->getConfig()['guestuser']['config']['guestuser_message_update_email']);
                break;

            case 'register-email-api':
                $subject = $settings->get('guestuserapi_message_confirm_registration_subject',
                    $this->getConfig()['guestuserapi']['config']['guestuserapi_message_confirm_registration_subject']);
                $body = $settings->get('guestuserapi_message_confirm_registration',
                    $this->getConfig()['guestuserapi']['config']['guestuserapi_message_confirm_registration']);
                break;

            case 'register-email-api-text':
                $subject = $settings->get('guestuserapi_message_confirm_registration_subject',
                    $this->getConfig()['guestuserapi']['config']['guestuserapi_message_confirm_registration_subject']);
                $body = $settings->get('guestuserapi_message_confirm_registration_text',
                    $this->getConfig()['guestuserapi']['config']['guestuserapi_message_confirm_registration_text']);
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
            'body'=> $body,
        ];
    }

    /**
     * Validate the API request and set global options.
     *
     * @param MvcEvent $event
     * @see \Omeka\Controller\ApiController::onDispatch()
     */
    public function onDispatch(MvcEvent $event)
    {
        $request = $this->getRequest();

        // Set pretty print.
        $prettyPrint = $request->getQuery('pretty_print');
        if (null !== $prettyPrint) {
            $this->setViewOption('pretty_print', true);
        }

        // Set the JSONP callback.
        $callback = $request->getQuery('callback');
        if (null !== $callback) {
            $this->setViewOption('callback', $callback);
        }

        try {
            // Finish dispatching the request.

            // TODO Action for /api/register: check json or multiform as other.
            $action = $event->getRouteMatch()->getParam('action', false);
            if ($action !== 'register') {
                $this->checkContentType($request);
            }

            parent::onDispatch($event);
        } catch (\Exception $e) {
            $this->logger()->err((string) $e);
            return $this->getErrorResult($event, $e);
        }
    }

    /**
     * Process post data and call create
     *
     * This method is overridden from the AbstractRestfulController to allow
     * processing of multipart POSTs.
     *
     * @param Request $request
     * @return mixed
     * @see \Omeka\Controller\ApiController::processPostData()
     */
    public function processPostData(Request $request)
    {
        $contentType = $request->getHeader('content-type');
        if ($contentType->match('multipart/form-data')) {
            $content = $request->getPost('data');
            $fileData = $request->getFiles()->toArray();
        } else {
            $content = $request->getContent();
            $fileData = [];
        }
        $data = $this->jsonDecode($content);
        return $this->create($data, $fileData);
    }

    /**
     * Set a view model option.
     *
     * @param string $key
     * @param mixed $value
     * @see \Omeka\Controller\ApiController::setViewOption()
     */
    public function setViewOption($key, $value)
    {
        $this->viewOptions[$key] = $value;
    }

    /**
     * Get all view options.
     *
     * return array
     * @see \Omeka\Controller\ApiController::getViewOption()
     */
    public function getViewOptions()
    {
        return $this->viewOptions;
    }

    /**
     * Check request content-type header to require JSON for methods with payloads.
     *
     * @param Request $request
     * @throws Exception\UnsupportedMediaTypeException
     * @see \Omeka\Controller\ApiController::checkContentType()
     */
    protected function checkContentType(Request $request)
    {
        // Require application/json Content-Type for certain methods.
        $method = strtolower($request->getMethod());
        $contentType = $request->getHeader('content-type');
        if (in_array($method, ['post', 'put', 'patch'])
            && (
                !$contentType
                || !$contentType->match(['application/json', 'multipart/form-data'])
            )
        ) {
            $contentType = $request->getHeader('Content-Type');
            $errorMessage = sprintf(
                'Invalid Content-Type header. Expecting "application/json", got "%s".',
                $contentType ? $contentType->getMediaType() : 'none'
            );

            throw new Exception\UnsupportedMediaTypeException($errorMessage);
        }
    }

    /**
     * Set an error result to the MvcEvent and return the result.
     *
     * @param MvcEvent $event
     * @param \Exception $error
     * @see \Omeka\Controller\ApiController::getErrorResult()
     */
    protected function getErrorResult(MvcEvent $event, \Exception $error)
    {
        $result = new ApiJsonModel(null, $this->getViewOptions());
        $result->setException($error);

        $event->setResult($result);
        return $result;
    }

    /**
     * Decode a JSON string.
     *
     * Override ZF's default to always use json_decode and to add error checking.'
     *
     * @param string
     * @return mixed
     * @throws Exception\InvalidJsonException on JSON decoding errors or if the
     * content is a scalar.
     * @see \Omeka\Controller\ApiController::jsonDecode()
     */
    protected function jsonDecode($string)
    {
        $content = json_decode($string, (bool) $this->jsonDecodeType);

        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new Exception\InvalidJsonException('JSON: ' . json_last_error_msg());
        }

        if (!is_array($content)) {
            throw new Exception\InvalidJsonException('JSON: Content must be an object or array.');
        }
        return $content;
    }

    /**
     * @return \Zend\Authentication\AuthenticationService
     */
    protected function getAuthenticationService()
    {
        return $this->authenticationService;
    }

    /**
     * @return \Doctrine\ORM\EntityManager
     */
    protected function getEntityManager()
    {
        return $this->entityManager;
    }

    /**
     * @return array
     */
    protected function getConfig()
    {
        return $this->config;
    }
}
