<?php

namespace GuestUserApi;

require_once dirname(__DIR__) . '/GuestUser/src/Module/AbstractGenericModule.php';

use GuestUser\Module\AbstractGenericModule;
use Zend\Mvc\MvcEvent;

class Module extends AbstractGenericModule
{
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

        $acl->allow(
            [\GuestUser\Permissions\Acl::ROLE_GUEST],
            [\GuestUserApi\Controller\ApiController::class],
            [
                'logout', 'update-account', 'update-email', 'update-phone',
                'me', 'accept-terms',
            ]
        );
    }
}
