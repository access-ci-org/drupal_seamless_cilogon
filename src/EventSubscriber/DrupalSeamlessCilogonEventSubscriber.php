<?php

namespace Drupal\drupal_seamless_cilogon\EventSubscriber;

use Drupal\Component\Utility\Html;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Extension\ModuleHandlerInterface;
use Drupal\Core\Logger\LoggerChannelFactoryInterface;
use Drupal\Core\Messenger\MessengerInterface;
use Drupal\Core\Routing\TrustedRedirectResponse;
use Drupal\Core\Session\AccountProxyInterface;
use Drupal\Core\Session\SessionManagerInterface;
use Drupal\Core\State\StateInterface;
use Drupal\Core\Routing\RouteMatchInterface;
use Drupal\Core\StringTranslation\StringTranslationTrait;
use Drupal\Core\Utility\Token;
use Drupal\openid_connect\OpenIDConnectClaims;
use Drupal\openid_connect\Plugin\OpenIDConnectClientManager;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\KernelEvents;

/**
 * Event Subscriber DrupalSeamlessCilogonEventSubscriber.
 */
class DrupalSeamlessCilogonEventSubscriber implements EventSubscriberInterface {

  use StringTranslationTrait;

  // For pantheon, cookie name must follow pattern S+ESS[a-z0-9]+
  // (see https://docs.pantheon.io/cookies#cache-busting-cookies)
  const SEAMLESSCOOKIENAME = 'SESSaccesscisso';

  // The OpenID Connect client plugin id used for the seamless flow. Shared
  // source of truth for the plugin instance and its config lookup.
  const CLIENT_NAME = 'cilogon';

  /**
   * The state service.
   *
   * @var \Drupal\Core\State\StateInterface
   */
  protected $state;

  /**
   * The config factory.
   *
   * @var \Drupal\Core\Config\ConfigFactoryInterface
   */
  protected $configFactory;

  /**
   * The current user.
   *
   * @var \Drupal\Core\Session\AccountProxyInterface
   */
  protected $currentUser;

  /**
   * The route match.
   *
   * @var \Drupal\Core\Routing\RouteMatchInterface
   */
  protected $routeMatch;

  /**
   * The logger factory.
   *
   * @var \Drupal\Core\Logger\LoggerChannelFactoryInterface
   */
  protected $loggerFactory;

  /**
   * The request stack.
   *
   * @var \Symfony\Component\HttpFoundation\RequestStack
   */
  protected $requestStack;

  /**
   * The messenger service.
   *
   * @var \Drupal\Core\Messenger\MessengerInterface
   */
  protected $messenger;

  /**
   * The token service.
   *
   * @var \Drupal\Core\Utility\Token
   */
  protected $token;

  /**
   * The module handler.
   *
   * @var \Drupal\Core\Extension\ModuleHandlerInterface
   */
  protected $moduleHandler;

  /**
   * The session manager.
   *
   * @var \Drupal\Core\Session\SessionManagerInterface
   */
  protected $sessionManager;

  /**
   * The OpenID Connect client plugin manager.
   *
   * @var \Drupal\openid_connect\Plugin\OpenIDConnectClientManager
   */
  protected $openidConnectPluginManager;

  /**
   * The OpenID Connect claims service.
   *
   * @var \Drupal\openid_connect\OpenIDConnectClaims
   */
  protected $claims;

  /**
   * Constructs the event subscriber.
   *
   * @param \Drupal\Core\State\StateInterface $state
   *   The state service.
   * @param \Drupal\Core\Config\ConfigFactoryInterface $config_factory
   *   The config factory.
   * @param \Drupal\Core\Session\AccountProxyInterface $current_user
   *   The current user.
   * @param \Drupal\Core\Routing\RouteMatchInterface $route_match
   *   The route match.
   * @param \Drupal\Core\Logger\LoggerChannelFactoryInterface $logger_factory
   *   The logger factory.
   * @param \Symfony\Component\HttpFoundation\RequestStack $request_stack
   *   The request stack.
   * @param \Drupal\Core\Messenger\MessengerInterface $messenger
   *   The messenger service.
   * @param \Drupal\Core\Utility\Token $token
   *   The token service.
   * @param \Drupal\Core\Extension\ModuleHandlerInterface $module_handler
   *   The module handler.
   * @param \Drupal\Core\Session\SessionManagerInterface $session_manager
   *   The session manager.
   * @param \Drupal\openid_connect\Plugin\OpenIDConnectClientManager $openid_connect_plugin_manager
   *   The OpenID Connect client plugin manager.
   * @param \Drupal\openid_connect\OpenIDConnectClaims $claims
   *   The OpenID Connect claims service.
   */
  public function __construct(
    StateInterface $state,
    ConfigFactoryInterface $config_factory,
    AccountProxyInterface $current_user,
    RouteMatchInterface $route_match,
    LoggerChannelFactoryInterface $logger_factory,
    RequestStack $request_stack,
    MessengerInterface $messenger,
    Token $token,
    ModuleHandlerInterface $module_handler,
    SessionManagerInterface $session_manager,
    OpenIDConnectClientManager $openid_connect_plugin_manager,
    OpenIDConnectClaims $claims,
  ) {
    $this->state = $state;
    $this->configFactory = $config_factory;
    $this->currentUser = $current_user;
    $this->routeMatch = $route_match;
    $this->loggerFactory = $logger_factory;
    $this->requestStack = $request_stack;
    $this->messenger = $messenger;
    $this->token = $token;
    $this->moduleHandler = $module_handler;
    $this->sessionManager = $session_manager;
    $this->openidConnectPluginManager = $openid_connect_plugin_manager;
    $this->claims = $claims;
  }

  /**
   * Event handler for KernelEvents::REQUEST <events>.
   *
   * Support seamless login by checking if a non-authenticated user already
   * has already been through seamless login.
   */
  public function onRequest(RequestEvent $event): void {

    if (!$event->isMainRequest()) {
      return;
    }

    if (!$this->verifyDomainIsAsp()) {
      return;
    }

    $seamless_login_enabled = $this->state->get('drupal_seamless_cilogon.seamless_login_enabled', TRUE);
    if (!$seamless_login_enabled) {
      return;
    }

    // Don't attempt to redirect if openid_connect_cilogon_client not installed.
    if (!$this->moduleHandler->moduleExists('openid_connect_cilogon_client')) {
      return;
    }

    $user_is_authenticated = $this->currentUser->isAuthenticated();
    $route_name = $this->routeMatch->getRouteName();
    $cookie_name = self::SEAMLESSCOOKIENAME;
    $current_request = $this->requestStack->getCurrentRequest();
    $cookie_exists = NULL !== $current_request->cookies->get($cookie_name);
    $seamless_debug = $this->state->get('drupal_seamless_cilogon.seamless_cookie_debug', FALSE);

    // Check if we just set the cookie in the session (it won't be in
    // the request yet)
    $request = $this->requestStack->getCurrentRequest();
    $session = $request->getSession();
    $cookie_just_set = $session->get('seamless_cilogon_cookie_was_set', FALSE);

    if ($seamless_debug) {
      $cookie_value_safe = $cookie_exists ? Html::escape((string) $current_request->cookies->get($cookie_name)) : '<not set>';
      $auth_status = $user_is_authenticated ? "TRUE" : "FALSE";
      $cookie_status = $cookie_exists ? "TRUE (value: $cookie_value_safe)" : "FALSE";
      $just_set_status = $cookie_just_set ? "TRUE" : "FALSE";
      $msg = __FUNCTION__ . "() ------- route_name = $route_name"
        . ", user_is_authenticated = $auth_status"
        . ", cookie exists = $cookie_status"
        . ", cookie_just_set = $just_set_status"
        . ' -- ' . basename(__FILE__) . ':' . __LINE__;
      // Only log to watchdog, don't show to user (XSS risk)
      error_log('seamless: ' . $msg);
      $this->loggerFactory->get('drupal_seamless_cilogon')->notice($msg);
    }

    // If coming back from cilogon, mark that we need to set the cookie.
    if ($route_name === 'openid_connect.redirect_controller_redirect') {
      if (!$cookie_exists) {
        // Store on request attributes (not session) because
        // user_login_finalize() regenerates the session, which would
        // wipe a session-based flag before onResponse() can read it.
        $request->attributes->set('seamless_cilogon_set_cookie', TRUE);

        if ($seamless_debug) {
          $msg = __FUNCTION__ . "() - Marked to set cookie on callback route"
            . ' -- ' . basename(__FILE__) . ':' . __LINE__;
          $this->loggerFactory->get('drupal_seamless_cilogon')->notice($msg);
        }
      }
      // Let the request continue to process the callback.
      return;
    }

    // If logging out, delete the cookie and redirect to CILogon logout.
    if ($route_name === 'user.logout') {
      $this->doDeleteCookie($event, $seamless_debug, $cookie_name, $cookie_exists);
      return;
    }

    // If the user is authenticated, no need to redirect to CILogon,
    // unless cookie doesn't exist, in which case, logout.
    if ($user_is_authenticated) {
      // Clear the "just set" flag if the cookie now exists. Do this before the
      // bypass early returns below, otherwise a first post-login request to an
      // API route or by a bypassed role would leave the flag stuck forever,
      // permanently disabling the safety logout.
      if ($cookie_exists && $cookie_just_set) {
        $session->remove('seamless_cilogon_cookie_was_set');
      }

      // Skip SSO cookie enforcement for API routes or service accounts.
      // - API routes: machine-to-machine; the SSO cookie is a browser concept.
      // - Service accounts (e.g. mcp_bot): authenticate via /user/login, not
      //   CILogon, so they will never have the SSO cookie.
      $path = $request->getPathInfo();
      if (str_starts_with($path, '/api/') || str_starts_with($path, '/jsonapi/')) {
        return;
      }
      $bypass_roles = ['mcp_bot', 'administrator'];
      $user_roles = $this->currentUser->getRoles();
      if (array_intersect($bypass_roles, $user_roles)) {
        return;
      }

      // Unless cookie doesn't exist. In this case, logout.
      // BUT: Don't logout if we just set the cookie (it won't be in
      // the request yet)
      if (
        !$cookie_exists &&
        !$cookie_just_set &&
        $route_name !== 'user.logout' &&
        $route_name !== 'user.login' &&
        $route_name !== 'user.logout.confirm'
      ) {
        // Programmatically log out the user instead of redirecting to
        // logout URL.
        user_logout();

        // Redirect to CILogon logout.
        $destination = 'https://cilogon.org/logout/?skin=access';
        $redir = new TrustedRedirectResponse($destination, 302);
        $redir->headers->set('Cache-Control', 'public, max-age=0');
        $redir->addCacheableDependency($destination);
        $event->setResponse($redir);
      }

      return;
    }

    // If here -- user is anonymous.  If cookie exists, redirect to cilogon.
    if ($cookie_exists) {
      $this->doRedirectToCilogon($event, $seamless_debug);
    }
  }

  /**
   * Set cookie on response if marked during request.
   *
   * @param \Symfony\Component\HttpKernel\Event\ResponseEvent $event
   *   Response event.
   */
  public function onResponse(ResponseEvent $event): void {
    if (!$event->isMainRequest()) {
      return;
    }

    $request = $event->getRequest();

    // Check if we need to set the cookie (flag set on request attributes
    // in onRequest, which survives session regeneration during login).
    // Only set the cookie if the user actually authenticated. If they cancel
    // at the CILogon consent screen or the IdP errors out, the callback route
    // still runs but the user remains anonymous; setting the cookie then would
    // bounce them back to CILogon on every page view until the cookie expires.
    if ($request->attributes->get('seamless_cilogon_set_cookie') && $this->currentUser->isAuthenticated()) {
      $request->attributes->remove('seamless_cilogon_set_cookie');

      $cookie_name = self::SEAMLESSCOOKIENAME;
      $site_name = $this->configFactory->get('system.site')->get('name');
      $cookie_value = $this->state->get('drupal_seamless_cilogon.seamless_cookie_value', $site_name);
      $cookie_expiration_setting = $this->state->get('drupal_seamless_cilogon.seamless_cookie_expiration', '+18 hours');
      // strtotime() returns FALSE on an invalid value (e.g. a typo), which
      // would cast to 0 and produce an immediately-expired cookie. Fall back
      // to the default expiration in that case.
      $cookie_expiration = strtotime($cookie_expiration_setting);
      if ($cookie_expiration === FALSE) {
        $cookie_expiration = strtotime('+18 hours');
      }
      $cookie_domain = $this->getEffectiveCookieDomain();

      $cookie = new Cookie($cookie_name, $cookie_value, $cookie_expiration, '/', $cookie_domain);

      $response = $event->getResponse();
      $response->headers->setCookie($cookie);

      // Mark that we just set the cookie so we don't logout on next request.
      $request->getSession()->set('seamless_cilogon_cookie_was_set', TRUE);

      $seamless_debug = $this->state->get('drupal_seamless_cilogon.seamless_cookie_debug', FALSE);
      if ($seamless_debug) {
        $domain_str = $cookie_domain ?? '(current host)';
        $msg = __FUNCTION__ . "() - Set cookie on response: name = $cookie_name, value = $cookie_value, expiration = "
          . date("Y-m-d H:i:s", $cookie_expiration) . ", domain = $domain_str"
          . ' -- ' . basename(__FILE__) . ':' . __LINE__;
        $this->loggerFactory->get('drupal_seamless_cilogon')->notice($msg);
      }
    }
  }

  /**
   * Delete the cookie, then redirect to CILogon logout.
   *
   * Always redirects to CILogon logout to clear CILogon's session,
   * even if the seamless cookie doesn't exist (e.g. expired).
   *
   * @param \Symfony\Component\HttpKernel\Event\RequestEvent $event
   *   Request event.
   * @param bool $seamless_debug
   *   Whether debug mode is enabled.
   * @param string $cookie_name
   *   The cookie name to delete.
   * @param bool $cookie_exists
   *   Whether the cookie currently exists in the request.
   */
  protected function doDeleteCookie(RequestEvent $event, bool $seamless_debug, string $cookie_name, bool $cookie_exists = TRUE): void {

    $cookie_domain = $this->getEffectiveCookieDomain();

    user_logout();

    $destination = 'https://cilogon.org/logout/?skin=access';

    $redir = new TrustedRedirectResponse($destination, 302);
    $redir->headers->set('Cache-Control', 'public, max-age=0');
    $redir->addCacheableDependency($destination);

    // Always send an expired cookie to ensure deletion, even if we didn't
    // detect it in the request (e.g. timing or domain mismatch edge cases).
    $expireCookie = new Cookie($cookie_name, '', 1, '/', $cookie_domain);
    $redir->headers->setCookie($expireCookie);

    $event->setResponse($redir);

    if ($seamless_debug) {
      $msg = __FUNCTION__ . "() - destination = $destination"
        . ", cookie_exists = " . ($cookie_exists ? "TRUE" : "FALSE")
        . " ---- unset cookie"
        . ' -- ' . basename(__FILE__) . ':' . __LINE__;
      error_log('seamless: ' . $msg);
      $this->loggerFactory->get('drupal_seamless_cilogon')->notice($msg);
    }
  }

  /**
   * Redirect to Cilogon.
   *
   * @param \Symfony\Component\HttpKernel\Event\RequestEvent $event
   *   Response event.
   * @param bool $seamless_debug
   *   Whether debug mode is enabled.
   */
  protected function doRedirectToCilogon(RequestEvent $event, bool $seamless_debug): void {
    $request = $event->getRequest();

    // \Drupal::service('page_cache_kill_switch')->trigger();
    // Setup redirect to CILogon flow.
    // Check if the middleware redirected us here with a 'redirect' param
    // containing the original destination (e.g. /user?redirect=%2Fsome%2Fpage).
    // Note: Symfony already URL-decodes query param values, so no urldecode().
    $redirect_param = $request->query->get('redirect');
    if ($redirect_param) {
      // Validate it's a relative path to prevent open redirects.
      if (str_starts_with($redirect_param, '/') && !str_starts_with($redirect_param, '//')) {
        $parsed = parse_url($redirect_param);
        $destination_path = $parsed['path'] ?? '/';
        $destination_query = $parsed['query'] ?? NULL;
      }
      else {
        $destination_path = NULL;
        $destination_query = NULL;
      }
    }
    else {
      $destination_path = NULL;
      $destination_query = NULL;
    }

    // Resolve the path and query for the post-login destination.
    // When we have a destination from the middleware's redirect param, use it
    // (including its query, which may be NULL). Otherwise fall back to the
    // current request's path and query.
    if ($destination_path !== NULL) {
      $dest_path = $destination_path;
      $dest_query = $destination_query;
    }
    else {
      $dest_path = $request->getPathInfo();
      $dest_query = $request->getQueryString();
    }

    // Ensure the PHP session is started before writing to $_SESSION.
    // For anonymous users the session may not be active yet; without this,
    // $_SESSION writes are lost when $client->authorize() internally calls
    // session_start() via OpenIDConnectStateToken::create(), which resets
    // $_SESSION to empty.
    if (session_status() === PHP_SESSION_NONE) {
      $this->sessionManager->start();
    }

    $config_name = 'openid_connect.settings.' . self::CLIENT_NAME;
    $configuration = $this->configFactory->get($config_name)->get('settings');

    try {
      $client = $this->openidConnectPluginManager->createInstance(self::CLIENT_NAME, $configuration);

      // Set destination in session for openid_connect.
      // Must use array format: [$path, ['query' => $queryString]]
      // to match OpenIDConnectSession::saveDestination().
      $_SESSION['openid_connect_op'] = 'login';
      $_SESSION['openid_connect_destination'] = [
        $dest_path,
        [
          'query' => $dest_query,
        ],
      ];

      // Get scopes via the claims service rather than the client's
      // getClientScopes() directly. getScopes() adds the scope for any
      // configured userinfo_mapping the client doesn't already request (e.g. a
      // future mapping under phone, address, or a custom scope); calling the
      // client directly would silently drop those claims on the seamless path.
      $scopes = $this->claims->getScopes($client);
      $response = $client->authorize($scopes);
    }
    catch (\Throwable $e) {
      // On a misconfigured site, $configuration is NULL and createInstance()
      // throws a TypeError (OpenIDConnectClientBase::__construct requires an
      // array). Without this guard the SSO cookie persists across requests, so
      // every anonymous visit would trigger another 500. Log a warning and let
      // the request continue normally instead.
      $this->loggerFactory->get('drupal_seamless_cilogon')->warning(
        'Seamless CILogon redirect aborted: @message',
        ['@message' => $e->getMessage()]
      );
      return;
    }

    $response->headers->set('Cache-Control', 'public, max-age=0');
    $event->setResponse($response);

    if ($seamless_debug) {
      $dest_str = $dest_path . ($dest_query ? '?' . $dest_query : '');
      $dest_str .= $redirect_param ? " (from redirect param)" : '';
      $msg = __FUNCTION__ . "() - destination = " . $dest_str . " using openid_connect"
        . ' -- ' . basename(__FILE__) . ':' . __LINE__;
      error_log('seamless: ' . $msg);
      $this->loggerFactory->get('drupal_seamless_cilogon')->notice($msg);
    }
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

    $domainName = $this->t("[domain:name]");
    $current_domain_name = Html::getClass($this->token->replace($domainName));

    $domain_verified = $current_domain_name === 'access-support';

    $seamless_debug = $this->state->get('drupal_seamless_cilogon.seamless_cookie_debug', FALSE);
    if ($seamless_debug) {
      $domain_status = $domain_verified ? 'TRUE' : 'FALSE';
      $msg = __FUNCTION__ . "() - current_domain_name = [" . $current_domain_name
        . '] so verifyDomainIsAsp() returns ' . $domain_status
        . ' -- ' . basename(__FILE__) . ':' . __LINE__;
      $this->messenger->addStatus($msg);
    }

    // Return true if the current domain is 'access-support'.
    return $domain_verified;
  }

  /**
   * Get the effective cookie domain for the current request.
   *
   * If the current request host is a subdomain of the configured cookie
   * domain, use the configured domain (for cross-subdomain SSO). Otherwise,
   * fall back to the current request host so the cookie works on environments
   * like Pantheon multidevs (e.g. md-2681-accessmatch.pantheonsite.io).
   *
   * @return string|null
   *   The cookie domain to use, or NULL to use the current host only.
   */
  protected function getEffectiveCookieDomain() {
    // Normalize the configured value: trim stray whitespace and lowercase it.
    // Hostnames are case-insensitive, so an admin entering ".ACCESS-CI.org" or
    // a value with surrounding whitespace must still match. Without this the
    // comparison below silently fails and cross-subdomain SSO breaks.
    $configured_domain = strtolower(trim($this->state->get('drupal_seamless_cilogon.seamless_cookie_domain', '.access-ci.org')));
    $host = strtolower($this->requestStack->getCurrentRequest()->getHost());

    // Normalize: ensure configured domain has leading dot for comparison.
    $match_domain = ltrim($configured_domain, '.');

    // If the host is the configured domain itself or a subdomain of it, use it.
    if ($host === $match_domain || str_ends_with($host, '.' . $match_domain)) {
      return $configured_domain;
    }

    // Host doesn't match configured domain (e.g. Pantheon multidev).
    // Return NULL so Symfony Cookie scopes to the current host only.
    return NULL;
  }

  /**
   * Subscribe to onRequest and onResponse events.
   *
   * Check if a CILogon redirect is needed any time a page is requested.
   *
   * {@inheritdoc}
   */
  public static function getSubscribedEvents() {
    $events[KernelEvents::REQUEST][] = ['onRequest', 31];
    $events[KernelEvents::RESPONSE][] = ['onResponse', -10];
    return $events;
  }

}
