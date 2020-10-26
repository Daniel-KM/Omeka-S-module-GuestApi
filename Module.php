<?php declare(strict_types=1);

namespace GuestApi;

if (!class_exists(\Generic\AbstractModule::class)) {
    require file_exists(dirname(__DIR__) . '/Generic/AbstractModule.php')
        ? dirname(__DIR__) . '/Generic/AbstractModule.php'
        : __DIR__ . '/src/Generic/AbstractModule.php';
}

use Generic\AbstractModule;
use GuestApi\Form\ConfigForm;
use Laminas\EventManager\Event;
use Laminas\EventManager\SharedEventManagerInterface;
use Laminas\Mvc\MvcEvent;
use Laminas\View\Renderer\PhpRenderer;

class Module extends AbstractModule
{
    const NAMESPACE = __NAMESPACE__;

    protected $dependency = 'Guest';

    /**
     * {@inheritDoc}
     * @see \Omeka\Module\AbstractModule::onBootstrap()
     * @todo Find the right way to load Guest before other modules in order to add role.
     */
    public function onBootstrap(MvcEvent $event): void
    {
        parent::onBootstrap($event);

        // Manage the dependency upon Guest, in particular when upgrading.
        // Once disabled, this current method and other ones are no more called.
        if (!$this->isModuleActive($this->dependency)) {
            $this->disableModule(__NAMESPACE__);
            return;
        }

        $this->addAclRoleAndRules();
    }

    protected function postInstall(): void
    {
        // Upgrade from GuestUserApi, if old settings are present.
        // Old settings are renamed from "guestuserapi_*" to "guestuser_*".
        $filepath = $this->modulePath() . '/data/install/install_post.sql';
        $this->execSqlFromFile($filepath);
    }

    /**
     * Add ACL role and rules for this module.
     */
    protected function addAclRoleAndRules(): void
    {
        /** @var \Omeka\Permissions\Acl $acl */
        $services = $this->getServiceLocator();
        $acl = $services->get('Omeka\Acl');

        $settings = $services->get('Omeka\Settings');
        $isApiOpenRegister = $settings->get('guestapi_open', 'moderate');
        if ($isApiOpenRegister === 'closed') {
            $acl->allow(
                null,
                [\GuestApi\Controller\ApiController::class],
                ['login', 'session-token', 'logout']
            );
        } else {
            $acl->allow(
                null,
                [\GuestApi\Controller\ApiController::class],
                ['login', 'session-token', 'logout', 'register']
            );
            $acl->allow(
                null,
                [\Omeka\Entity\User::class],
                // Change role and Activate user should be set to allow external
                // logging (ldap, saml, etc.), not only guest registration here.
                ['create', 'change-role', 'activate-user']
            );
            $acl->allow(
                null,
                [\Omeka\Api\Adapter\UserAdapter::class],
                'create'
            );
        }

        // This is an api, so all rest api actions are allowed.
        $acl->allow(
            $acl->getRoles(),
            [\GuestApi\Controller\ApiController::class]
        );
    }

    public function attachListeners(SharedEventManagerInterface $sharedEventManager): void
    {
        // This filter is used after other ones.
        $sharedEventManager->attach(
            \Omeka\Api\Representation\UserRepresentation::class,
            'rep.resource.json',
            [$this, 'filterEntityJsonLd'],
            -100
        );

        $sharedEventManager->attach(
            \Omeka\Api\Adapter\UserAdapter::class,
            'api.create.post',
            [$this, 'handleUserPost']
        );
        $sharedEventManager->attach(
            \Omeka\Api\Adapter\UserAdapter::class,
            'api.update.post',
            [$this, 'handleUserPost']
        );
    }

    /**
     * Remove some properties for the user.
     *
     * @todo Remove this filter, or move it into module Group.
     * @param Event $event
     */
    public function filterEntityJsonLd(Event $event): void
    {
        $services = $this->getServiceLocator();
        /** @var \Laminas\Authentication\AuthenticationService $authentication */
        $authentication = $services->get('Omeka\AuthenticationService');
        $user = $services->get('Omeka\AuthenticationService')->getIdentity();
        if ($user && $user->getRole() !== \Guest\Permissions\Acl::ROLE_GUEST) {
            return;
        }
        $jsonLd = $event->getParam('jsonLd');
        unset($jsonLd['o-module-group:group']);
        $event->setParam('jsonLd', $jsonLd);
    }

    /**
     * Handle hydration for user data: manage the password.
     *
     * @param Event $event
     */
    public function handleUserPost(Event $event): void
    {
        /**
         * @var \Omeka\Api\Request $request
         * @var \Omeka\Api\Response $response
         * @var \Omeka\Entity\User $user
         */
        $request = $event->getParam('request');
        $userData = $request->getContent();
        if (empty($userData['o:password'])) {
            return;
        }

        $services = $this->getServiceLocator();
        $entityManager = $services->get('Omeka\EntityManager');

        $response = $event->getParam('response');
        $user = $response->getContent();
        $user->setPassword($userData['o:password']);
        $entityManager->persist($user);

        // The entity manager may be flushed or not.
        if ($request->getOption('flushEntityManager', true)) {
            $entityManager->flush();
        }
    }
}
