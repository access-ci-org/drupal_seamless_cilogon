<?php

namespace Drupal\drupal_seamless_cilogon\Form;

use Drupal\drupal_seamless_cilogon\EventSubscriber\DrupalSeamlessCilogonEventSubscriber;
use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\Form\FormBase;

/**
 * Class DrupalSeamlessCilogon
 */  
class DrupalSeamlessCilogon extends FormBase
{

  /**
   * {@inheritdoc}
   */
  public function buildForm(array $form, FormStateInterface $form_state)
  {
    $seamless_debug = \Drupal::state()->get('drupal_seamless_cilogon.seamless_cookie_debug', false);

    $seamless_login_enabled = \Drupal::state()->get('drupal_seamless_cilogon.seamless_login_enabled', true);

    // coookie name must start with SESS and have no underscores.  
    // So it is hardcoded in the event subscriber.  So removed following from config.
    //
    // $cookie_name = \Drupal::state()->get(
    //   'drupal_seamless_cilogon.seamless_cookie_name',
    //   DrupalSeamlessCilogonEventSubscriber::SEAMLESSCOOKIENAME
    // );

    $site_name = \Drupal::config('system.site')->get('name');
    $cookie_value = \Drupal::state()->get('drupal_seamless_cilogon.seamless_cookie_value', $site_name);
    $cookie_domain = \Drupal::state()->get('drupal_seamless_cilogon.seamless_cookie_domain', '.access-ci.org');
    $cookie_expiration = \Drupal::state()->get('drupal_seamless_cilogon.seamless_cookie_expiration', '+18 hours');

    $form['seamless_login_enabled'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Enable seamless redirect to CILogon?'),
      '#description' => $this->t('Disable this for testing.'),
      '#default_value' => $seamless_login_enabled,
    ];

    // $form['seamless_cookie_name'] = [
    //   '#type' => 'textfield',
    //   '#title' => $this->t('Seamless CILogin - cookie name'),
    //   '#maxlength' => 255,
    //   '#default_value' => $cookie_name,
    //   '#description' => $this->t("Name for the seamless login cookie.  Default value is " 
    //     . DrupalSeamlessCilogonEventSubscriber::SEAMLESSCOOKIENAME),
    //   '#required' => false,
    // ];

    $form['seamless_cookie_value'] = [
      '#type' => 'textfield',
      '#title' => $this->t('Cookie value'),
      '#maxlength' => 255,
      '#default_value' => $cookie_value,
      '#description' => $this->t("Value for the cookie."),
      '#required' => false,
    ];

    $form['seamless_cookie_domain'] = [
      '#type' => 'textfield',
      '#title' => $this->t('Cookie domain'),
      '#maxlength' => 255,
      '#default_value' => $cookie_domain,
      '#description' => $this->t('domain for cookie - default is ".access-ci.org"'),
    ];

    $form['seamless_cookie_expiration'] = [
      '#type' => 'textfield',
      '#title' => $this->t('Cookie expiration (as argument to strtotime()'),
      '#maxlength' => 255,
      '#default_value' => $cookie_expiration,
      '#description' => $this->t('Example:  "+18 hours" sets expiration to 18 hours from now')
    ];

    $form['seamless_cookie_debug'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Enable debug logging?'),
      '#description' => $this->t('Logging will go to screen when possible, and to drupal log with label "seamless_cilogon"'),
      '#default_value' => $seamless_debug,
    ];

    $form['save_seamless_settings'] = [
      '#type' => 'submit',
      '#value' => $this->t('Save Seamless CILogon Settings'),
      '#submit' => [[$this, 'doSaveSeamlessSettings']],
    ];
    return $form;
  }

  /**
   * Getter method for Form ID.
   *
   * @return string
   *   The unique ID of the form defined by this class.
   */
  public function getFormId()
  {
    return 'drupal_seamless_cilogon_form';
  }

  // TODO -- Implements any form validation?  Maybe especially for the cookie expiration ?
  
  /**
   * {@inheritdoc}
   */
  public function submitForm(array &$form, FormStateInterface $form_state)
  {
    parent::submitForm($form, $form_state);
  }

  /**
   *
   */
  public function doSaveSeamlessSettings(array &$form, FormStateInterface $form_state)
  {
    \Drupal::state()->set('drupal_seamless_cilogon.seamless_login_enabled', $form_state->getValue('seamless_login_enabled'));
    // removed cookie name from config -- see comments
    // \Drupal::state()->set('drupal_seamless_cilogon.seamless_cookie_name', $form_state->getValue('seamless_cookie_name'));
    \Drupal::state()->set('drupal_seamless_cilogon.seamless_cookie_value', $form_state->getValue('seamless_cookie_value'));
    \Drupal::state()->set('drupal_seamless_cilogon.seamless_cookie_domain', $form_state->getValue('seamless_cookie_domain'));
    \Drupal::state()->set('drupal_seamless_cilogon.seamless_cookie_expiration', $form_state->getValue('seamless_cookie_expiration'));

    $seamless_debug = $form_state->getValue('seamless_cookie_debug');
    \Drupal::state()->set('drupal_seamless_cilogon.seamless_cookie_debug', $seamless_debug);

    if ($seamless_debug) {
      
      $seamless_login_enabled = \Drupal::state()->get('drupal_seamless_cilogon.seamless_login_enabled', true);
      $cookie_name = \Drupal::state()->get(
        'drupal_seamless_cilogon.seamless_cookie_name',
        DrupalSeamlessCilogonEventSubscriber::SEAMLESSCOOKIENAME
      );
      $site_name = \Drupal::config('system.site')->get('name');
      $cookie_value = \Drupal::state()->get('drupal_seamless_cilogon.seamless_cookie_value', $site_name);
      $cookie_expiration = \Drupal::state()->get('drupal_seamless_cilogon.seamless_cookie_expiration', '+18 hours');
      $cookie_domain = \Drupal::state()->get('drupal_seamless_cilogon.seamless_cookie_domain', '.access-ci.org');
      $seamless_debug = \Drupal::state()->get('drupal_seamless_cilogon.seamless_cookie_debug', false);

      $msg =  __FUNCTION__ . "(): seamless_login_enabled=$seamless_login_enabled cookie_name=$cookie_name cookie_value=$cookie_value cookie_domain=$cookie_domain cookie_expiration=$cookie_expiration seamless_debug=$seamless_debug"
        . ' -- ' . basename(__FILE__) . ':' . __LINE__ ;  
      \Drupal::messenger()->addStatus($msg);
      \Drupal::logger('seamless_cilogon')->debug($msg);
    }
  }
}
