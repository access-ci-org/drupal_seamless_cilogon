<?php

namespace Drupal\drupal_seamless_cilogon\StackMiddleware;

use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Extension\ModuleHandlerInterface;
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
   * The logging channel.
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
   * The module handler.
   *
   * @var \Drupal\Core\Extension\ModuleHandlerInterface
   */
  protected $moduleHandler;

  /**
   * The entity type manager.
   *
   * @var \Drupal\Core\Entity\EntityTypeManagerInterface
   */
  protected $entityTypeManager;

  /**
   * Constructs a CookieMiddleware object.
   *
   * @param \Symfony\Component\HttpKernel\HttpKernelInterface $httpKernel
   *   The decorated kernel.
   * @param \Drupal\Core\Logger\LoggerChannelFactoryInterface $loggerFactory
   *   The logger factory service.
   * @param \Drupal\Core\State\StateInterface $state
   *   The state key/value store.
   * @param \Drupal\Core\Extension\ModuleHandlerInterface $moduleHandler
   *   The module handler service.
   * @param \Drupal\Core\Entity\EntityTypeManagerInterface $entityTypeManager
   *   The entity type manager.
   */
  public function __construct(
    HttpKernelInterface $httpKernel,
    LoggerChannelFactoryInterface $loggerFactory,
    StateInterface $state,
    ModuleHandlerInterface $moduleHandler,
    EntityTypeManagerInterface $entityTypeManager,
  ) {
    $this->httpKernel = $httpKernel;
    $this->logger = $loggerFactory->get('drupal_seamless_cilogon');
    $this->state = $state;
    $this->moduleHandler = $moduleHandler;
    $this->entityTypeManager = $entityTypeManager;
  }

  /**
   * Sets the HTTP kernel.
   *
   * @param \Symfony\Component\HttpKernel\HttpKernelInterface $kernel
   *   The HTTP kernel to wrap.
   */
  public function setHttpKernel(HttpKernelInterface $kernel) {
    $this->httpKernel = $kernel;
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

    if (!$this->verifyDomainIsAsp()) {
      if ($logging) {
        $this->logger->notice('verifyDomainIsAsp');
      }
      return $this->httpKernel->handle($request, $type, $catch);
    }

    $seamless_login_enabled = $this->state->get('drupal_seamless_cilogon.seamless_login_enabled', TRUE);
    if (!$seamless_login_enabled) {
      if ($logging) {
        $this->logger->notice('seamless_login_enabled');
      }
      return $this->httpKernel->handle($request, $type, $catch);
    }

    // Don't attempt to redirect if neither cilogon module is installed.
    if (!$this->moduleHandler->moduleExists('cilogon_auth') && !$this->moduleHandler->moduleExists('openid_connect_cilogon_client')) {
      if ($logging) {
        $this->logger->notice('module exists cilogon_auth or openid_connect_cilogon_client');
      }
      return $this->httpKernel->handle($request, $type, $catch);
    }

    $path = $request->getRequestUri();
    $arg = explode('/', $path);
    $cookie_name = $_COOKIE['SESSaccesscisso'] ?? NULL;
    $cookie_exists = NULL !== $cookie_name;

    if (str_starts_with($arg[1], 'user')) {
      if ($logging) {
        $this->logger->notice('/path: user');
      }
      return $this->httpKernel->handle($request, $type, $catch);
    }

    // If coming back from cilogon, set the cookie.
    // Support both old cilogon_auth and new openid_connect routes.
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

    // If the user has a Drupal session cookie, they are likely authenticated.
    // We cannot use \Drupal::currentUser() here because this middleware runs
    // before the session middleware resolves the user. Instead, check for the
    // Drupal session cookie directly: SESS<hex32> (HTTP) or
    // SSESS<hex32> (HTTPS).
    if ($this->hasSessionCookie($request)) {
      if ($logging) {
        $this->logger->notice('session cookie detected, passing through');
      }
      return $this->httpKernel->handle($request, $type, $catch);
    }

    // If here -- user is unauthenticated. If cookie exists, redirect to
    // cilogon.
    if ($cookie_exists) {
      if ($logging) {
        $this->logger->notice('redirect /user/login?redirect=path');
      }
      // Sanitize the request URI to prevent open redirects.
      $from = $request->getRequestUri();
      // Ensure it's a relative path (starts with /)
      if (!str_starts_with($from, '/')) {
        $from = '/';
      }
      // URL encode the path to prevent injection.
      $from_encoded = urlencode($from);
      $path = $request->getBasePath() . "/user/login?redirect=$from_encoded";
      return new RedirectResponse($path, 302, ['Cache-Control' => 'no-cache']);
    }

    return $this->httpKernel->handle($request, $type, $catch);
  }

  /**
   * Check if the request has a Drupal session cookie.
   *
   * Drupal session cookies follow the pattern SESS<hex32> (HTTP) or
   * SSESS<hex32> (HTTPS). This is used as a proxy for authentication
   * in middleware, where \Drupal::currentUser() is not yet resolved.
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The current request.
   *
   * @return bool
   *   TRUE if a Drupal session cookie is present.
   */
  protected function hasSessionCookie(Request $request) {
    foreach ($request->cookies->all() as $name => $value) {
      if (preg_match('/^S?SESS[a-f0-9]{32}$/', $name)) {
        return TRUE;
      }
    }
    return FALSE;
  }

  /**
   * Verifies if the domain access module is in use and current domain is ASP.
   *
   * The ACCESS support portal uses the domain access module. If this module
   * is in use, we only want to set cookies for the 'access-support' module.
   * This function checks if the domain access module is in use, and if so,
   * returns FALSE if the current domain name is not 'access-support'.
   * Otherwise it returns true.
   *
   * @return bool
   *   Whether to proceed with the cookie logic in invoking code.
   */
  protected function verifyDomainIsAsp() {
    // Verify the domain module is installed.  If not installed,
    // return true to proceed to CILogon.
    if (!$this->moduleHandler->moduleExists('domain')) {
      return TRUE;
    }

    $domain_storage = $this->entityTypeManager->getStorage('domain');
    $current_domain_name = $domain_storage->loadDefaultId();

    $domain_verified = $current_domain_name === 'amp_cyberinfrastructure_org';

    // Return true if the current domain is 'access-support'.
    return $domain_verified;
  }

}
