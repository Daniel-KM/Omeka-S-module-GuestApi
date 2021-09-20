<?php declare(strict_types=1);
namespace GuestApi;

/**
 * @var Module $this
 * @var \Laminas\ServiceManager\ServiceLocatorInterface $serviceLocator
 * @var string $newVersion
 * @var string $oldVersion
 *
 * @var \Doctrine\DBAL\Connection $connection
 * @var \Doctrine\ORM\EntityManager $entityManager
 * @var \Omeka\Api\Manager $api
 */
$services = $serviceLocator;
$settings = $services->get('Omeka\Settings');
// $config = require dirname(dirname(__DIR__)) . '/config/module.config.php';
$connection = $services->get('Omeka\Connection');
// $entityManager = $services->get('Omeka\EntityManager');
// $plugins = $services->get('ControllerPluginManager');
// $api = $plugins->get('api');
// $space = strtolower(__NAMESPACE__);

if (version_compare($oldVersion, '3.1.1', '<')) {
    $settings->set('guestapi_open', $settings->get('guestapi_register') ? 'open' : 'closed');
    $settings->delete('guestapi_register');
}

if (version_compare($oldVersion, '3.3.3.3.3', '<')) {
    $module = $services->get('Omeka\ModuleManager')->getModule('Generic');
    if ($module && version_compare($module->getIni('version') ?? '', '3.3.27', '<')) {
        $translator = $services->get('MvcTranslator');
        $message = new \Omeka\Stdlib\Message(
            $translator->translate('This module requires the module "%s", version %s or above.'), // @translate
            'Generic', '3.3.27'
        );
        throw new \Omeka\Module\Exception\ModuleCannotInstallException((string) $message);
    }
}
