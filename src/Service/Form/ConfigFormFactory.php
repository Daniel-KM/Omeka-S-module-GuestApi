<?php
namespace GuestApi\Service\Form;

use Interop\Container\ContainerInterface;
use GuestApi\Form\ConfigForm;
use Zend\ServiceManager\Factory\FactoryInterface;

class ConfigFormFactory implements FactoryInterface
{
    public function __invoke(ContainerInterface $services, $requestedName, array $options = null)
    {
        /** @var \Omeka\Permissions\Acl $acl */
        $acl = $services->get('Omeka\Acl');
        $rolesList = $acl->getRoles();
        $roleLabels = $acl->getRoleLabels();
        $roles = [];
        foreach ($rolesList as $role) {
            $roles[$role] = isset($roleLabels[$role]) ? $roleLabels[$role] : $role;
        }

        $form = new ConfigForm(null, $options);
        $form->setRoles($roles);
        return $form;
    }
}