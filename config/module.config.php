<?php
namespace GuestUserApi;

return [
    'view_manager' => [
        'strategies' => [
            'ViewJsonStrategy',
        ],
    ],
    'form_elements' => [
        'invokables' => [
            Form\ConfigForm::class => Form\ConfigForm::class,
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
                    'guest-user' => [
                        'type' => \Zend\Router\Http\Segment::class,
                        'options' => [
                            'route' => '/user[/:id]',
                            'defaults' => [
                                'controller' => Controller\ApiController::class,
                            ],
                        ],
                    ],
                    'guest-user-register' => [
                        'type' => \Zend\Router\Http\Literal::class,
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
    'guestuserapi' => [
        'config' => [
            'guestuserapi_register' => false,
            'guestuserapi_register_site' => false,
            'guestuserapi_register_email_is_valid' => false,
            'guestuserapi_message_confirm_registration_subject' => 'Welcome to {main_title}!', // @translate
            'guestuserapi_message_confirm_register' => 'Thank you for registering. Please check your email for a confirmation message. Once you have confirmed your request, you will be able to log in.', // @translate
            'guestuserapi_message_confirm_registration' => '<p>Hi {user_name},</p>
<p>You have registered for an account on {main_title} / {site_title} ({site_url}).</p>
<p>Please confirm your registration by following this link: {token_url}.</p>
<p>If you did not request to join {main_title} please disregard this email.</p>', // @translate
            'guestuserapi_message_confirm_registration_text' => 'Hi {user_name},
You have registered for an account on {main_title} / {site_title} ({site_url}).
Please confirm your registration by following this link: {token_url}.
If you did not request to join {main_title} please disregard this email.', // @translate
        ],
    ],
];
