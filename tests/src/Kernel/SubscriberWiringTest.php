<?php

namespace Drupal\Tests\drupal_seamless_cilogon\Kernel;

use Drupal\Core\PageCache\ChainRequestPolicy;
use Drupal\Core\PageCache\RequestPolicyInterface;
use Drupal\KernelTests\KernelTestBase;
use Drupal\drupal_seamless_cilogon\PageCache\DenySeamlessCookie;
use Symfony\Component\HttpFoundation\Request;

/**
 * The subscriber's container wiring (D8-2896).
 *
 * LogoutCookieTest covers the logout logic, but it builds the subscriber with
 * `new` and passes all thirteen arguments itself. That proves the method
 * bodies and nothing about the service definition, so these two failures both
 * ship green:
 *
 * - services.yml drifting from the constructor signature. The page-cache kill
 *   switch was added as a constructor argument for this work; a missing or
 *   misordered entry in the YAML is a container error on every request, and a
 *   hand-built subscriber never reads the YAML.
 * - the subscriber silently not being registered for an event it needs.
 *
 * Cheap to run: no schemas, no HTTP dispatch, just the compiled container.
 *
 * @group drupal_seamless_cilogon
 */
class SubscriberWiringTest extends KernelTestBase {

  const SERVICE = 'drupal_seamless_cilogon_event_subscriber';

  /**
   * {@inheritdoc}
   *
   * The subscriber's constructor takes two openid_connect services, so the
   * container cannot build it without those modules.
   */
  protected static $modules = [
    'system',
    'user',
    'file',
    'openid_connect',
    'openid_connect_cilogon_client',
    'drupal_seamless_cilogon',
  ];

  /**
   * The container can build the subscriber as services.yml declares it.
   *
   * Guards the YAML against the constructor signature. Without this, adding
   * or reordering an argument and forgetting the YAML is a fatal on every
   * production request that no test would catch.
   */
  public function testContainerBuildsTheSubscriber(): void {
    $subscriber = $this->container->get(self::SERVICE);

    $this->assertInstanceOf(
      'Drupal\drupal_seamless_cilogon\EventSubscriber\DrupalSeamlessCilogonEventSubscriber',
      $subscriber,
      'services.yml resolves to a usable subscriber.',
    );
  }

  /**
   * The subscriber listens on both kernel events it needs.
   *
   * It decides who is logged in at REQUEST and clears cookies at RESPONSE.
   * Losing either registration disables half the module silently.
   */
  public function testSubscriberIsRegisteredForBothEvents(): void {
    $events = $this->container->get(self::SERVICE)::getSubscribedEvents();

    $this->assertArrayHasKey('kernel.request', $events, 'Listens on REQUEST.');
    $this->assertArrayHasKey('kernel.response', $events, 'Listens on RESPONSE.');
  }

  /**
   * The CookieMiddleware service is gone and the cookie policy is wired in.
   *
   * The chain's CommandLineOrUnsafeMethod rule denies every CLI request, so
   * the chain's result alone cannot show this policy's effect. The test checks
   * that the policy is collected into the chain, then calls the policy
   * directly on a GET request with and without the cookie.
   */
  public function testSeamlessCookieIsDeniedByPageCachePolicy(): void {
    $this->assertFalse(
      $this->container->has('http_middleware.CookieMiddleware'),
      'The http_middleware.CookieMiddleware service is removed.',
    );

    $chain = $this->container->get('page_cache_request_policy');
    $rules = (new \ReflectionProperty(ChainRequestPolicy::class, 'rules'))->getValue($chain);
    $this->assertNotEmpty(
      array_filter($rules, static fn($rule) => $rule instanceof DenySeamlessCookie),
      'The seamless cookie policy is collected into page_cache_request_policy.',
    );

    $with_cookie = Request::create('/', 'GET', [], ['SESSaccesscisso' => 'x']);
    $this->assertSame(
      RequestPolicyInterface::DENY,
      $chain->check($with_cookie),
      'The chain denies a request carrying the seamless cookie.',
    );

    $policy = $this->container->get('drupal_seamless_cilogon.page_cache_request_policy.deny_seamless_cookie');
    $this->assertSame(
      RequestPolicyInterface::DENY,
      $policy->check($with_cookie),
      'The policy denies a GET request carrying the seamless cookie.',
    );
    $this->assertNull(
      $policy->check(Request::create('/', 'GET')),
      'The policy leaves a GET request without the cookie undecided.',
    );
  }

}
