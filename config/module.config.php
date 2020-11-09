<?php declare(strict_types=1);

namespace GuestApi;

return [
    'view_manager' => [
        'strategies' => [
            'ViewJsonStrategy',
        ],
    ],
    'form_elements' => [
        'invokables' => [
            Form\Element\OptionalSelect::class => Form\Element\OptionalSelect::class,
        ],
        'factories' => [
            Form\ConfigForm::class => Service\Form\ConfigFormFactory::class,
        ],
    ],
    'controllers' => [
        'factories' => [
            Controller\ApiController::class => Service\Controller\ApiControllerFactory::class,
        ],
    ],
    'router' => [
        'routes' => [
            'api' => [
                'child_routes' => [
                    'guest' => [
                        'type' => \Laminas\Router\Http\Literal::class,
                        'options' => [
                            'route' => '/users/me',
                            'defaults' => [
                                'controller' => Controller\ApiController::class,
                                'resource' => 'users',
                                'id' => 'me',
                            ],
                        ],
                    ],
                    'guest-login' => [
                        'type' => \Laminas\Router\Http\Literal::class,
                        'options' => [
                            'route' => '/login',
                            'defaults' => [
                                'controller' => Controller\ApiController::class,
                                'action' => 'login',
                            ],
                        ],
                    ],
                    'guest-logout' => [
                        'type' => \Laminas\Router\Http\Literal::class,
                        'options' => [
                            'route' => '/logout',
                            'defaults' => [
                                'controller' => Controller\ApiController::class,
                                'action' => 'logout',
                            ],
                        ],
                    ],
                    'guest-session-token' => [
                        'type' => \Laminas\Router\Http\Literal::class,
                        'options' => [
                            'route' => '/session-token',
                            'defaults' => [
                                'controller' => Controller\ApiController::class,
                                'action' => 'session-token',
                            ],
                        ],
                    ],
                    'guest-register' => [
                        'type' => \Laminas\Router\Http\Literal::class,
                        'options' => [
                            'route' => '/register',
                            'defaults' => [
                                'controller' => Controller\ApiController::class,
                                'action' => 'register',
                            ],
                        ],
                    ],
                ],
            ],
        ],
    ],
    'translator' => [
        'translation_file_patterns' => [
            [
                'type' => 'gettext',
                'base_dir' => dirname(__DIR__) . '/language',
                'pattern' => '%s.mo',
                'text_domain' => null,
            ],
        ],
    ],
    'guestapi' => [
        'config' => [
            'guestapi_open' => 'moderate',
            'guestapi_register_site' => false,
            'guestapi_register_email_is_valid' => false,
            'guestapi_message_confirm_registration_subject' => 'Welcome to {main_title}!', // @translate
            'guestapi_message_confirm_register' => 'Thank you for registering. Please check your email for a confirmation message. Once you have confirmed your request, you will be able to log in.', // @translate
            'guestapi_message_confirm_registration' => '<p>Hi {user_name},</p>
<p>You have registered for an account on {main_title} / {site_title} ({site_url}).</p>
<p>Please confirm your registration by following this link: {token_url}.</p>
<p>If you did not request to join {main_title} please disregard this email.</p>', // @translate
            'guestapi_message_confirm_registration_text' => 'Hi {user_name},
You have registered for an account on {main_title} / {site_title} ({site_url}).
Please confirm your registration by following this link: {token_url}.
If you did not request to join {main_title} please disregard this email.', // @translate
            'guestapi_login_roles' => [
                'annotator',
                'contributor',
                'guest',
            ],
            'guestapi_login_session' => false,
            'guestapi_cors' => [],
        ],
    ],
];
