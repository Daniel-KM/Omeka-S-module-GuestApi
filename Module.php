<?php

namespace GuestUserApi;

if (!class_exists(\Generic\AbstractModule::class)) {
    require file_exists(dirname(__DIR__) . '/Generic/AbstractModule.php')
        ? dirname(__DIR__) . '/Generic/AbstractModule.php'
        : __DIR__ . '/src/Generic/AbstractModule.php';
}

use Generic\AbstractModule;
use Zend\EventManager\Event;
use Zend\EventManager\SharedEventManagerInterface;
use Zend\Mvc\MvcEvent;

class Module extends AbstractModule
{
    const NAMESPACE = __NAMESPACE__;

    protected $dependency = 'GuestUser';

    /**
     * {@inheritDoc}
     * @see \Omeka\Module\AbstractModule::onBootstrap()
     * @todo Find the right way to load GuestUser before other modules in order to add role.
     */
    public function onBootstrap(MvcEvent $event)
    {
        parent::onBootstrap($event);

        // Manage the dependency upon GuestUser, in particular when upgrading.
        // Once disabled, this current method and other ones are no more called.
        if (!$this->isModuleActive($this->dependency)) {
            $this->disableModule(__NAMESPACE__);
            return;
        }

        $this->addAclRoleAndRules();
    }

    /**
     * Add ACL role and rules for this module.
     */
    protected function addAclRoleAndRules()
    {
        /** @var \Zend\Permissions\Acl $acl */
        $services = $this->getServiceLocator();
        $acl = $services->get('Omeka\Acl');

        $settings = $services->get('Omeka\Settings');
        $isApiOpenRegister = $settings->get('guestuserapi_register', false);
        if ($isApiOpenRegister) {
            $acl->allow(
                null,
                [\GuestUserApi\Controller\ApiController::class],
                ['register']
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
            [\GuestUser\Permissions\Acl::ROLE_GUEST],
            [\GuestUserApi\Controller\ApiController::class]
        );
    }

    public function attachListeners(SharedEventManagerInterface $sharedEventManager)
    {
        // This filter is used after other ones.
        $sharedEventManager->attach(
            \Omeka\Api\Representation\UserRepresentation::class,
            'rep.resource.json',
            [$this, 'filterEntityJsonLd'],
            -100
        );
    }

    /**
     * Remove some properties for the user.
     *
     * @param Event $event
     */
    public function filterEntityJsonLd(Event $event)
    {
        $services = $this->getServiceLocator();
        /** @var AuthenticationService $authentication */
        $authentication =  $services->get('Omeka\AuthenticationService');
        $user = $services->get('Omeka\AuthenticationService')->getIdentity();
        if ($user && $user->getRole() !== \GuestUser\Permissions\Acl::ROLE_GUEST) {
            return;
        }
        $jsonLd = $event->getParam('jsonLd');
        unset($jsonLd['o-module-group:group']);
        $event->setParam('jsonLd', $jsonLd);
    }
}
