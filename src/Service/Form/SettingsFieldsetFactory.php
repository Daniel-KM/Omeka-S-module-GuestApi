<?php declare(strict_types=1);

namespace GuestApi\Service\Form;

use GuestApi\Form\SettingsFieldset;
use Interop\Container\ContainerInterface;
use Laminas\ServiceManager\Factory\FactoryInterface;

class SettingsFieldsetFactory implements FactoryInterface
{
    public function __invoke(ContainerInterface $services, $requestedName, array $options = null)
    {
        /** @var \Omeka\Permissions\Acl $acl */
        $acl = $services->get('Omeka\Acl');
        $rolesList = $acl->getRoles();
        $roleLabels = $acl->getRoleLabels();
        $roles = [];
        foreach ($rolesList as $role) {
            $roles[$role] = $roleLabels[$role] ?? $role;
        }

        $form = new SettingsFieldset(null, $options ?? []);
        return $form
            ->setRoles($roles);
    }
}
