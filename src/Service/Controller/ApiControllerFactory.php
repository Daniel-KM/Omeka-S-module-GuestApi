<?php
namespace GuestApi\Service\Controller;

use GuestApi\Controller\ApiController;
use Interop\Container\ContainerInterface;
use Omeka\Authentication\Adapter\PasswordAdapter;
use Omeka\Authentication\Storage\DoctrineWrapper;
use Zend\Authentication\AuthenticationService;
use Zend\Authentication\Storage\Session;
use Zend\ServiceManager\Factory\FactoryInterface;

class ApiControllerFactory implements FactoryInterface
{
    public function __invoke(ContainerInterface $services, $requestedName, array $options = null)
    {
        // The user is automatically authenticated via api, but when an option
        // is set, the user should be authenticalted vai the local session too.
        $entityManager = $services->get('Omeka\EntityManager');
        $userRepository = $entityManager->getRepository('Omeka\Entity\User');
        $storage = new DoctrineWrapper(new Session, $userRepository);
        $adapter = new PasswordAdapter($userRepository);
        $passwordAuthService = new AuthenticationService($storage, $adapter);
        return new ApiController(
            $services->get('Omeka\Paginator'),
            $services->get('Omeka\ApiManager'),
            $services->get('Omeka\AuthenticationService'),
            $passwordAuthService,
            $services->get('Omeka\EntityManager'),
            $services->get('Config')
        );
    }
}
