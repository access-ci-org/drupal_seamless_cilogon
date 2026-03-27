<?php

namespace Drupal\drupal_seamless_cilogon\EventSubscriber;

use Drupal\Component\Utility\Html;
use Drupal\Component\Utility\Xss;
use Drupal\Core\Routing\TrustedRedirectResponse;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\KernelEvents;

/**
 * Event Subscriber DrupalSeamlessCilogonEventSubscriber.
 */
class DrupalSeamlessCilogonEventSubscriber implements EventSubscriberInterface {

  // For pantheon, cookie name must follow pattern S+ESS[a-z0-9]+
  // (see https://docs.pantheon.io/cookies#cache-busting-cookies)
  const SEAMLESSCOOKIENAME = 'SESSaccesscisso';

  /**
   * Event handler for KernelEvents::REQUEST <events>.
   *
   * Support seamless login by checking if a non-authenticated user already
   * has already been through seamless login.
   */
  public function onRequest(RequestEvent $event) {

    if (!$event->isMainRequest()) {
      return;
    }

    if (!$this->verify_domain_is_asp()) {
      return;
    }

    $seamless_login_enabled = \Drupal::state()->get('drupal_seamless_cilogon.seamless_login_enabled', TRUE);
    if (!$seamless_login_enabled) {
      return;
    }

    // Don't attempt to redirect if neither cilogon module is installed.
    $moduleHandler = \Drupal::service('module_handler');
    if (!$moduleHandler->moduleExists('cilogon_auth') && !$moduleHandler->moduleExists('openid_connect_cilogon_client')) {
      return;
    }

    $user_is_authenticated = \Drupal::currentUser()->isAuthenticated();
    $route_name = \Drupal::routeMatch()->getRouteName();
    $cookie_name = self::SEAMLESSCOOKIENAME;
    $cookie_exists = NULL !== \Drupal::service('request_stack')->getCurrentRequest()->cookies->get($cookie_name);
    $seamless_debug = \Drupal::state()->get('drupal_seamless_cilogon.seamless_cookie_debug', FALSE);
    
    // Check if we just set the cookie in the session (it won't be in the request yet)
    $request = \Drupal::request();
    $session = $request->getSession();
    $cookie_just_set = $session->get('seamless_cilogon_cookie_was_set', FALSE);

    if ($seamless_debug) {
      $cookie_value_safe = $cookie_exists ? Html::escape($_COOKIE[$cookie_name]) : '<not set>';
      $msg = __FUNCTION__ . "() ------- route_name = $route_name"
        . ", user_is_authenticated = " . ($user_is_authenticated ? "TRUE" : "FALSE")
        . ", cookie exists = " . ($cookie_exists ? "TRUE (value: $cookie_value_safe)" : "FALSE")
        . ", cookie_just_set = " . ($cookie_just_set ? "TRUE" : "FALSE")
        . ' -- ' . basename(__FILE__) . ':' . __LINE__;
      // Only log to watchdog, don't show to user (XSS risk)
      error_log('seamless: ' . $msg);
      \Drupal::logger('drupal_seamless_cilogon')->notice($msg);
    }

    // If coming back from cilogon, mark that we need to set the cookie.
    // Support both old cilogon_auth and new openid_connect routes
    if ($route_name === 'cilogon_auth.redirect_controller_redirect' || 
        $route_name === 'openid_connect.redirect_controller_redirect') {
      if (!$cookie_exists) {
        // Store on request attributes (not session) because
        // user_login_finalize() regenerates the session, which would
        // wipe a session-based flag before onResponse() can read it.
        $request = \Drupal::request();
        $request->attributes->set('seamless_cilogon_set_cookie', TRUE);

        if ($seamless_debug) {
          $msg = __FUNCTION__ . "() - Marked to set cookie on callback route"
            . ' -- ' . basename(__FILE__) . ':' . __LINE__;
          \Drupal::logger('drupal_seamless_cilogon')->notice($msg);
        }
      }
      // Let the request continue to process the callback
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
      // Skip SSO cookie enforcement for API routes or service accounts.
      // - API routes: machine-to-machine; the SSO cookie is a browser concept.
      // - Service accounts (e.g. mcp_bot): authenticate via /user/login, not
      //   CILogon, so they will never have the SSO cookie.
      $path = $request->getPathInfo();
      if (str_starts_with($path, '/api/') || str_starts_with($path, '/jsonapi/')) {
        return;
      }
      $bypass_roles = ['mcp_bot', 'administrator'];
      $user_roles = \Drupal::currentUser()->getRoles();
      if (array_intersect($bypass_roles, $user_roles)) {
        return;
      }

      // Unless cookie doesn't exist. In this case, logout.
      // BUT: Don't logout if we just set the cookie (it won't be in the request yet)
      if (
        !$cookie_exists &&
        !$cookie_just_set &&
        $route_name !== 'user.logout' &&
        $route_name !== 'user.login' &&
        $route_name !== 'user.logout.confirm'
      ) {
        // Programmatically log out the user instead of redirecting to logout URL
        user_logout();
        
        // Redirect to CILogon logout
        $destination = 'https://cilogon.org/logout/?skin=access';
        $redir = new TrustedRedirectResponse($destination, '302');
        $redir->headers->set('Cache-Control', 'public, max-age=0');
        $redir->addCacheableDependency($destination);
        $event->setResponse($redir);
      }
      
      // Clear the "just set" flag if cookie now exists
      if ($cookie_exists && $cookie_just_set) {
        $session->remove('seamless_cilogon_cookie_was_set');
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
  public function onResponse(ResponseEvent $event) {
    if (!$event->isMainRequest()) {
      return;
    }

    $request = $event->getRequest();

    // Check if we need to set the cookie (flag set on request attributes
    // in onRequest, which survives session regeneration during login)
    if ($request->attributes->get('seamless_cilogon_set_cookie')) {
      $request->attributes->remove('seamless_cilogon_set_cookie');
      
      $cookie_name = self::SEAMLESSCOOKIENAME;
      $site_name = \Drupal::config('system.site')->get('name');
      $cookie_value = \Drupal::state()->get('drupal_seamless_cilogon.seamless_cookie_value', $site_name);
      $cookie_expiration = \Drupal::state()->get('drupal_seamless_cilogon.seamless_cookie_expiration', '+18 hours');
      $cookie_expiration = strtotime($cookie_expiration);
      $cookie_domain = \Drupal::state()->get('drupal_seamless_cilogon.seamless_cookie_domain', '.access-ci.org');
      
      $cookie = new Cookie($cookie_name, $cookie_value, $cookie_expiration, '/', $cookie_domain);
      
      $response = $event->getResponse();
      $response->headers->setCookie($cookie);
      
      // Mark that we just set the cookie so we don't logout on next request
      $request->getSession()->set('seamless_cilogon_cookie_was_set', TRUE);

      $seamless_debug = \Drupal::state()->get('drupal_seamless_cilogon.seamless_cookie_debug', FALSE);
      if ($seamless_debug) {
        $msg = __FUNCTION__ . "() - Set cookie on response: name = $cookie_name, value = $cookie_value, expiration = " 
          . date("Y-m-d H:i:s", $cookie_expiration) . ", domain = $cookie_domain"
          . ' -- ' . basename(__FILE__) . ':' . __LINE__;
        \Drupal::logger('drupal_seamless_cilogon')->notice($msg);
      }
    }
  }

  /**
   * Add the cookie, via a redirect.
   *
   * @param \Symfony\Component\HttpKernel\Event\RequestEvent $event
   *   Response event.   *.
   */
  protected function doSetCookie(RequestEvent $event, $seamless_debug, $cookie_name) {

    $site_name = \Drupal::config('system.site')->get('name');
    $cookie_value = \Drupal::state()->get('drupal_seamless_cilogon.seamless_cookie_value', $site_name);
    $cookie_expiration = \Drupal::state()->get('drupal_seamless_cilogon.seamless_cookie_expiration', '+18 hours');
    // Use value from form.
    $cookie_expiration = strtotime($cookie_expiration);
    $cookie_domain = \Drupal::state()->get('drupal_seamless_cilogon.seamless_cookie_domain', '.access-ci.org');
    $cookie = new Cookie($cookie_name, $cookie_value, $cookie_expiration, '/', $cookie_domain);

    $request = $event->getRequest();
    $destination = $request->getRequestUri();

    // @todo consider following
    // "MUST use service to turn of Internal Page Cache,
    // or else anonymous users will not ever be able to reach source page."
    // $this->killSwitch->trigger();
    // from https://www.drupal.org/project/adv_varnish/issues/3127566:
    // Another documented way is to call the killSwitch in your code:
    //
    // commenting this out to see unnecessary
    // \Drupal::service('page_cache_kill_switch')->trigger();
    $redir = new TrustedRedirectResponse($destination, '302');
    $redir->headers->setCookie($cookie);
    $redir->headers->set('Cache-Control', 'public, max-age=0');
    $redir->addCacheableDependency($destination);
    $redir->addCacheableDependency($cookie);

    $event->setResponse($redir);

    if ($seamless_debug) {
      $msg = __FUNCTION__ . "() - destination = $destination ---- set cookie:  name = $cookie_name, value = $cookie_value, expiration = $cookie_expiration "
        . " = " . date("Y-m-d H:i:s", $cookie_expiration) . ", domain = $cookie_domain"
        . ' -- ' . basename(__FILE__) . ':' . __LINE__;
      \Drupal::messenger()->addStatus($msg);
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
  protected function doDeleteCookie(RequestEvent $event, $seamless_debug, $cookie_name, $cookie_exists = TRUE) {

    $cookie_domain = \Drupal::state()->get('drupal_seamless_cilogon.seamless_cookie_domain', '.access-ci.org');

    user_logout();

    $destination = 'https://cilogon.org/logout/?skin=access';

    $redir = new TrustedRedirectResponse($destination, '302');
    $redir->headers->set('Cache-Control', 'public, max-age=0');
    $redir->addCacheableDependency($destination);

    // Use Symfony Cookie on the response headers for reliable deletion.
    if ($cookie_exists) {
      $expireCookie = new Cookie($cookie_name, '', strtotime('-1 hour'), '/', $cookie_domain);
      $redir->headers->setCookie($expireCookie);
      unset($_COOKIE[$cookie_name]);
    }

    $event->setResponse($redir);

    if ($seamless_debug) {
      $msg = __FUNCTION__ . "() - destination = $destination"
        . ", cookie_exists = " . ($cookie_exists ? "TRUE" : "FALSE")
        . " ---- unset cookie"
        . ' -- ' . basename(__FILE__) . ':' . __LINE__;
      error_log('seamless: ' . $msg);
      \Drupal::logger('drupal_seamless_cilogon')->notice($msg);
    }
  }

  /**
   * Redirect to Cilogon.
   *
   * @param \Symfony\Component\HttpKernel\Event\RequestEvent $event
   *   Response event.   *.
   */
  protected function doRedirectToCilogon(RequestEvent $event, $seamless_debug) {
    $request = $event->getRequest();

    // \Drupal::service('page_cache_kill_switch')->trigger();
    // Setup redirect to CILogon flow.
    $container = \Drupal::getContainer();
    $client_name = 'cilogon';
    
    // Try openid_connect first, fallback to cilogon_auth
    $moduleHandler = \Drupal::service('module_handler');
    $using_openid_connect = $moduleHandler->moduleExists('openid_connect_cilogon_client');
    
    // Check if the middleware redirected us here with a 'redirect' param
    // containing the original destination (e.g. /user?redirect=%2Fsome%2Fpage).
    $redirect_param = $request->query->get('redirect');
    if ($redirect_param) {
      // Validate it's a relative path to prevent open redirects.
      $decoded = urldecode($redirect_param);
      if (str_starts_with($decoded, '/') && !str_starts_with($decoded, '//')) {
        $parsed = parse_url($decoded);
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

    if ($using_openid_connect) {
      // Use openid_connect
      $config_name = 'openid_connect.settings.' . $client_name;
      $configuration = $container->get('config.factory')->get($config_name)->get('settings');
      $pluginManager = $container->get('plugin.manager.openid_connect_client');
      $client = $pluginManager->createInstance($client_name, $configuration);

      // Set destination in session for openid_connect.
      // Must use array format: [$path, ['query' => $queryString]]
      // to match OpenIDConnectSession::saveDestination().
      $path = $destination_path ?? $request->getPathInfo();
      $query = $destination_query ?? $request->getQueryString();

      $_SESSION['openid_connect_op'] = 'login';
      $_SESSION['openid_connect_destination'] = [
        $path,
        [
          'query' => $query,
        ],
      ];

      // Get scopes from client
      $scopes = implode(' ', $client->getClientScopes());
      $response = $client->authorize($scopes);
    }
    else {
      // Fallback to cilogon_auth (legacy)
      $config_name = 'cilogon_auth.settings.' . $client_name;
      $configuration = $container->get('config.factory')->get($config_name)->get('settings');
      $pluginManager = $container->get('plugin.manager.cilogon_auth_client.processor');
      $claims = $container->get('cilogon_auth.claims');
      $client = $pluginManager->createInstance($client_name, $configuration);
      $scopes = $claims->getScopes();

      $destination = $destination_path !== NULL
        ? $destination_path . ($destination_query ? '?' . $destination_query : '')
        : $request->getRequestUri();

      $_SESSION['cilogon_auth_op'] = 'login';
      $_SESSION['cilogon_auth_destination'] = $destination;

      $response = $client->authorize($scopes);
    }
    
    $response->headers->set('Cache-Control', 'public, max-age=0');
    $event->setResponse($response);

    if ($seamless_debug) {
      $dest_str = $using_openid_connect ? ($path ?? '') : ($destination ?? '');
      $dest_str .= $destination_path ? " (from redirect param: $destination_path)" : '';
      $msg = __FUNCTION__ . "() - destination = " . $dest_str . " using " . ($using_openid_connect ? 'openid_connect' : 'cilogon_auth')
        . ' -- ' . basename(__FILE__) . ':' . __LINE__;
      error_log('seamless: ' . $msg);
      \Drupal::logger('drupal_seamless_cilogon')->notice($msg);
    }
  }

  /**
   * The ACCESS support portal uses the domain access module.  If this module
   * is in use, we only want to set cookies for the 'access-support' module.
   *
   * This function checks if the domain access module is in use, and
   * if so, returns FALSE if the current domain name is not 'access-support'.
   *
   * Otherwise it returns true.
   *
   * @return bool
   *   Whether to proceed with the cookie logic in invoking code.
   */
  protected function verify_domain_is_asp() {
    // Verify the domain module is installed.  If not installed,
    // return true to proceed to CILogon.
    $moduleHandler = \Drupal::service('module_handler');
    if (!$moduleHandler->moduleExists('domain')) {
      return TRUE;
    }

    $token = \Drupal::token();
    $domainName = t("[domain:name]");
    $current_domain_name = Html::getClass($token->replace($domainName));

    $domain_verified = $current_domain_name === 'access-support';

    $seamless_debug = \Drupal::state()->get('drupal_seamless_cilogon.seamless_cookie_debug', FALSE);
    if ($seamless_debug) {
      $msg = __FUNCTION__ . "() - current_domain_name = [" . $current_domain_name
        . '] so verify_domain_is_asp() returns ' . ($domain_verified ? 'TRUE' : 'FALSE')
        . ' -- ' . basename(__FILE__) . ':' . __LINE__;
      \Drupal::messenger()->addStatus($msg);
    }

    // Return true if the current domain is 'access-support'.
    return $domain_verified;
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
