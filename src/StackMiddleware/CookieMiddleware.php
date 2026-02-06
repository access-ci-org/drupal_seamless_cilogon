<?php

namespace Drupal\drupal_seamless_cilogon\StackMiddleware;

use Drupal\Core\Logger\LoggerChannelFactoryInterface;
use Drupal\Core\State\StateInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\HttpKernelInterface;

/**
 * Provides a HTTP middleware.
 */
class CookieMiddleware implements HttpKernelInterface {

  /**
   * The wrapped HTTP kernel.
   *
   * @var \Symfony\Component\HttpKernel\HttpKernelInterface
   */
  protected $httpKernel;

  /**
   * The RedirectAddAnalytics logging channel.
   *
   * @var \Drupal\Core\Logger\LoggerChannelInterface
   */
  protected $logger;

  /**
   * The state key/value store.
   *
   * @var \Drupal\Core\State\StateInterface
   */
  protected $state;

  /**
   * Constructs a drupal_seamless_cilogin object.
   *
   * @param \Symfony\Component\HttpKernel\HttpKernelInterface $kernel
   *   The decorated kernel.
   * @param \Drupal\Core\Logger\LoggerChannelFactoryInterface $config_factory
   *   Logging interface.
   * @param \Drupal\Core\State\StateInterface $state
   *   The state key/value store.
   */
  public function __construct(
    HttpKernelInterface $http_kernel,
    LoggerChannelFactoryInterface $channelFactory,
    StateInterface $state
  ) {
    $this->httpKernel = $http_kernel;
    $this->logger = $channelFactory->get('drupal_seamless_cilogon');
    $this->state = $state;
  }

  /**
   * {@inheritdoc}
   */
  public function handle(Request $request, int $type = self::MAIN_REQUEST, bool $catch = TRUE): Response {
    $logging = $this->state->get('drupal_seamless_cilogon.logging');
    if (!$type) {
      if ($logging) {
        $this->logger->notice('type');
      }
      return $this->httpKernel->handle($request, $type, $catch);
    }

    if (!$this->verify_domain_is_asp()) {
      if ($logging) {
        $this->logger->notice('verify_domain_is_asp');
      }
      return $this->httpKernel->handle($request, $type, $catch);
    }

    $seamless_login_enabled = \Drupal::state()->get('drupal_seamless_cilogon.seamless_login_enabled', TRUE);
    if (!$seamless_login_enabled) {
      if ($logging) {
        $this->logger->notice('seamless_login_enabled');
      }
      return $this->httpKernel->handle($request, $type, $catch);
    }

    // Don't attempt to redirect if neither cilogon module is installed.
    $moduleHandler = \Drupal::service('module_handler');
    if (!$moduleHandler->moduleExists('cilogon_auth') && !$moduleHandler->moduleExists('openid_connect_cilogon_client')) {
      if ($logging) {
        $this->logger->notice('module exists cilogon_auth or openid_connect_cilogon_client');
      }
      return $this->httpKernel->handle($request, $type, $catch);
    }

    $user_is_authenticated = \Drupal::currentUser()->isAuthenticated();
    $path = $request->getRequestUri();
    $arg = explode('/', $path);
    $cookie_name = isset($_COOKIE['SESSaccesscisso']) ? $_COOKIE['SESSaccesscisso'] : NULL;
    $cookie_exists = NULL !== $cookie_name;

    if (str_starts_with($arg[1], 'user')) {
      if ($logging) {
        $this->logger->notice('/path: user');
      }
      return $this->httpKernel->handle($request, $type, $catch);
    }

    // If coming back from cilogon, set the cookie.
    // Support both old cilogon_auth and new openid_connect routes
    if ($arg[1] === 'cilogon-auth' || $arg[1] === 'openid-connect') {
      if ($logging) {
        $this->logger->notice('path: /cilogon-auth or /openid-connect');
      }
      return $this->httpKernel->handle($request, $type, $catch);
    }

    // If hitting the nc page, not cached and will pass.
    if ($arg[1] === 'nc') {
      if ($logging) {
        $this->logger->notice('path: /nc');
      }
      return $this->httpKernel->handle($request, $type, $catch);
    }

    // If the user is authenticated, no need to redirect to CILogon, unless cookie doesn't exist, in
    // which case, let the EventSubscriber handle the logout.
    if ($user_is_authenticated) {
      // The EventSubscriber will handle logout if cookie is missing
      return $this->httpKernel->handle($request, $type, $catch);
    }

    // If here -- user is unauthenticated.  If cookie exists, redirect to cilogon.
    if ($cookie_exists) {
      if ($logging) {
        $this->logger->notice('redirect /user?redirect=path');
      }
      $from = $request->getRequestUri();
      return new RedirectResponse($request->getBasePath() . "/user?redirect=$from", 302, ['Cache-Control' => 'no-cache']);
    }

    return $this->httpKernel->handle($request, $type, $catch);
  }

  /**
   * The ACCESS support portal uses the domain access module.  If this module
   * is in use, we only want to set cookies for the 'access-support'
   * module.
   *
   * This function checks if the domain access module is in use, and
   * if so, returns FALSE if the current domain name is not 'access-support'.
   *
   * Otherwise it returns true.
   *
   * @return bool whether to proceed with the cookie logic in invoking code
   */
  protected function verify_domain_is_asp() {
    // Verify the domain module is installed.  If not installed,
    // return true to proceed to CILogon.
    $moduleHandler = \Drupal::service('module_handler');
    if (!$moduleHandler->moduleExists('domain')) {
      return TRUE;
    }

    $domain_storage = \Drupal::entityTypeManager()->getStorage('domain');
    $current_domain_name = $domain_storage->loadDefaultId();

    $domain_verified = $current_domain_name === 'amp_cyberinfrastructure_org';

    // Return true if the current domain is 'access-support'.
    return $domain_verified;
  }

}
