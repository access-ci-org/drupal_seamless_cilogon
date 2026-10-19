<?php

namespace Drupal\Tests\drupal_seamless_cilogon\Kernel;

use Drupal\KernelTests\KernelTestBase;

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

}
