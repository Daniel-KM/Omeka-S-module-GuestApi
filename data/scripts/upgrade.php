<?php declare(strict_types=1);

namespace GuestApi;

use Omeka\Stdlib\Message;

/**
 * @var Module $this
 * @var \Laminas\ServiceManager\ServiceLocatorInterface $services
 * @var string $newVersion
 * @var string $oldVersion
 *
 * @var \Omeka\Api\Manager $api
 * @var \Omeka\Settings\Settings $settings
 * @var \Doctrine\DBAL\Connection $connection
 * @var \Doctrine\ORM\EntityManager $entityManager
 * @var \Omeka\Mvc\Controller\Plugin\Messenger $messenger
 */
$plugins = $services->get('ControllerPluginManager');
$api = $plugins->get('api');
$settings = $services->get('Omeka\Settings');
$urlPlugin = $plugins->get('url');
$connection = $services->get('Omeka\Connection');
$messenger = $plugins->get('messenger');
$entityManager = $services->get('Omeka\EntityManager');

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
            'Generic', '3.4.43'
        );
        throw new \Omeka\Module\Exception\ModuleCannotInstallException((string) $message);
    }
}

if (version_compare($oldVersion, '3.4.7', '<')) {
    $message = new \Common\Stdlib\PsrMessage(
        'The features of this module were integrated in module Guest since version 3.4.21, so check the {link_url}main settings{link_end} and uninstall it.', // @translate
        [
            'link_url' => sprintf('<a href="%s">', $urlPlugin->fromRoute('admin') . '/setting#guest'),
            'link_end' => '</a>',
        ]
    );
    $message->setEscapeHtml(false);
    $messenger->addWarning($message);
}
