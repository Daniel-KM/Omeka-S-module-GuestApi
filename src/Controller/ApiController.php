<?php
namespace GuestUserApi\Controller;

use Doctrine\ORM\EntityManager;
use GuestUser\Entity\GuestUserToken;
use GuestUser\Stdlib\PsrMessage;
use Omeka\Api\Representation\SiteRepresentation;
use Omeka\Entity\User;
use Omeka\Entity\SitePermission;
use Zend\Authentication\AuthenticationService;
use Zend\Http\Response;
use Zend\Mvc\Controller\AbstractRestfulController;
use Zend\View\Model\JsonModel;

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

    /**
     * @see \GuestUser\Controller\Site\GuestUserController::registerAction()
     *
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
        if ($settings->get('guestuser_api_register_site')) {
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

        $emailIsValid = $this->settings()->get('guestuser_api_register_email_is_valid');

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

                $message = $this->settings()->get('guestuser_api_message_confirm_register')
                    ?: $this->translate('Thank you for registering. Please check your email for a confirmation message. Once you have confirmed your request, you will be able to log in.'); // @translate
                return new JsonModel([
                    'status' => Response::STATUS_CODE_200,
                    'message' => $message,
                ]);
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
            $message = $this->settings()->get('guestuser_api_message_confirm_register')
                ?: $this->translate('Thank you for registering. You can now log in and use the library.'); // @translate
        } else {
            $message = $this->settings()->get('guestuser_api_message_confirm_register')
                ?: $this->translate('Thank you for registering. Please check your email for a confirmation message. Once you have confirmed your request, you will be able to log in.'); // @translate
        }
        return new JsonModel([
            'status' => Response::STATUS_CODE_200,
            'message' => $message,
        ]);
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
        return new JsonModel($result);
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
        if (empty($site)) {
            throw new \Exception('Missing site.');
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

        if ($data['token']) {
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
                $subject = $settings->get('guestuser_message_confirm_registration_subject_api',
                    $this->getConfig()['guestuser']['config']['guestuser_message_confirm_registration_subject_api']);
                $body = $settings->get('guestuser_message_confirm_registration_api',
                    $this->getConfig()['guestuser']['config']['guestuser_message_confirm_registration_api']);
                break;

            case 'register-email-api-text':
                $subject = $settings->get('guestuser_message_confirm_registration_subject_api',
                    $this->getConfig()['guestuser']['config']['guestuser_message_confirm_registration_subject_api']);
                $body = $settings->get('guestuser_message_confirm_registration_api_text',
                    $this->getConfig()['guestuser']['config']['guestuser_message_confirm_registration_api_text']);
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
