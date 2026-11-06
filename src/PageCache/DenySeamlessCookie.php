<?php

namespace Drupal\drupal_seamless_cilogon\PageCache;

use Drupal\Core\PageCache\RequestPolicyInterface;
use Drupal\drupal_seamless_cilogon\EventSubscriber\DrupalSeamlessCilogonEventSubscriber;
use Symfony\Component\HttpFoundation\Request;

/**
 * Denies page cache delivery to requests carrying the seamless SSO cookie.
 *
 * The page cache middleware (priority 200) answers before the event subscriber
 * runs, so a cached anonymous copy would be served to a returning SSO user and
 * never reach the redirect to CILogon. Denying lets those requests reach the
 * subscriber. Core's FinishResponseSubscriber reads the same policy chain, so
 * these responses also get non-cacheable headers, which keeps a shared or edge
 * cache from storing a cookie holder's response. Requests without the cookie
 * are unaffected.
 */
class DenySeamlessCookie implements RequestPolicyInterface {

  /**
   * {@inheritdoc}
   */
  public function check(Request $request) {
    if ($request->cookies->has(DrupalSeamlessCilogonEventSubscriber::SEAMLESSCOOKIENAME)) {
      return static::DENY;
    }
    return NULL;
  }

}
