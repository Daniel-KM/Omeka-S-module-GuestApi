<?php
namespace GuestApi\Form;

use Zend\Form\Element;
use Zend\Form\Form;

class ConfigForm extends Form
{
    /**
     * @var array
     */
    protected $roles;

    public function init()
    {
        $this
            ->add([
                'name' => 'guestapi_open',
                'type' => Element\Radio::class,
                'options' => [
                    'label' => 'Registration via api', // @translate
                    'info' => 'Allow guest user registration with or without administrator approval via api.', // @translate
                    'value_options' => [
                        'open' => 'Open to everyone', // @translate
                        // 'moderate' => 'Open with moderation', // @translate
                        'closed' => 'Closed to visitors', // @translate
                    ],
                ],
                'attributes' => [
                    'id' => 'guestapi_open',
                    'required' => true,
                ],
            ])
            ->add([
                'name' => 'guestapi_register_site',
                'type' => Element\Checkbox::class,
                'options' => [
                    'label' => 'Requires a site to register via api', // @translate
                    'info' => 'If checked, a site id or slug will be required when registering via api. Note: when this setting is set, all previous users must be added to a site.', // @translate
                ],
                'attributes' => [
                    'id' => 'guestapi_register_site',
                ],
            ])
            ->add([
                'name' => 'guestapi_register_email_is_valid',
                'type' => Element\Checkbox::class,
                'options' => [
                    'label' => 'Validate email set by api', // @translate
                    'info' => 'If checked, the user won’t have to validate his email, so he will be able to login directly.', // @translate
                ],
                'attributes' => [
                    'id' => 'guestapi_register_email_is_valid',
                ],
            ])
            ->add([
                'name' => 'guestapi_message_confirm_register',
                'type' => Element\Textarea::class,
                'options' => [
                    'label' => 'Message to confirm registration via api', // @translate
                    'info' => 'The text of the response to confirm the registration via api.', // @translate
                ],
                'attributes' => [
                    'id' => 'guestapi_message_confirm_register',
                    'placeholder' => 'Thank you for registering. Please check your email for a confirmation message. Once you have confirmed your request, you will be able to log in.', // @translate
                ],
            ])
            ->add([
                'name' => 'guestapi_message_confirm_registration_subject',
                'type' => Element\Text::class,
                'options' => [
                    'label' => 'Subject of message to confirm registration via api', // @translate
                    'info' => 'The subject of the email to confirm the registration via api.', // @translate
                ],
                'attributes' => [
                    'id' => 'guestapi_message_confirm_registration_subject',
                    'placeholder' => 'Welcome to {main_title}!', // @translate
                ],
            ])
            ->add([
                'name' => 'guestapi_message_confirm_registration',
                'type' => Element\Textarea::class,
                'options' => [
                    'label' => 'Email sent to confirm registration via api (html)', // @translate
                    'info' => 'The text of the email to confirm a registration done via email and to send the token.', // @translate
                ],
                'attributes' => [
                    'id' => 'guestapi_message_confirm_registration',
                    'placeholder' => '<p>Hi {user_name},</p>
    <p>You have registered for an account on {main_title} / {site_title} ({site_url}).</p>
    <p>Please confirm your registration by following this link: {token_url}.</p>
    <p>If you did not request to join {main_title} please disregard this email.</p>', // @translate
                ],
            ])
            ->add([
                'name' => 'guestapi_message_confirm_registration_text',
                'type' => Element\Textarea::class,
                'options' => [
                    'label' => 'Email sent to confirm registration via api (text)', // @translate
                    'info' => 'The text version of the mail above. When the two version are filled, they are sent both.', // @translate
                ],
                'attributes' => [
                    'id' => 'guestapi_message_confirm_registration_text',
                    'placeholder' => 'Hi {user_name},
    You have registered for an account on {main_title} / {site_title} ({site_url}).
    Please confirm your registration by following this link: {token_url}.
    If you did not request to join {main_title} please disregard this email.', // @translate
                ],
            ])
            ->add([
                'name' => 'guestapi_login_roles',
                'type' => \Zend\Form\Element\Select::class,
                'options' => [
                    'label' => 'Roles that can login', // @translate
                    'info' => 'To allow full access via api increases risks of intrusion.', // @translate
                    'empty_option' => '',
                    'value_options' => $this->getRoles(),
                ],
                'attributes' => [
                    'id' => 'guestapi_login_roles',
                    'multiple' => true,
                    'required' => false,
                    'class' => 'chosen-select',
                    'data-placeholder' => 'Select roles…', // @translate
                ],
            ])
        ;

        $this->getInputFilter()
            ->add([
                'name' => 'guestapi_login_roles',
                'allow_empty' => true,
                'required' => false,
            ])
        ;
    }

    public function setRoles(array $roles)
    {
        $this->roles = $roles;
        return $this;
    }

    protected function getRoles()
    {
        return $this->roles;
    }
}
