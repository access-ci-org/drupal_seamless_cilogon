<?php

namespace Drupal\Tests\drupal_seamless_cilogon\Kernel;

use Drupal\Core\PageCache\ChainRequestPolicy;
use Drupal\Core\PageCache\RequestPolicy\CommandLineOrUnsafeMethod;
use Drupal\Core\PageCache\RequestPolicy\NoSessionOpen;
use Drupal\Core\PageCache\RequestPolicyInterface;
use Drupal\Core\Session\SessionConfigurationInterface;
use Drupal\domain\Entity\Domain;
use Drupal\KernelTests\KernelTestBase;
use Drupal\drupal_seamless_cilogon\PageCache\DenySeamlessCookie;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Page cache must not answer returning SSO users (D8-2966).
 *
 * Core's page_cache middleware (priority 200) runs before the module's
 * kernel.request subscriber (priority 31). A cached anonymous copy was
 * therefore served to a returning ACCESS user carrying the SESSaccesscisso
 * cookie, and the redirect to CILogon never happened. DenySeamlessCookie is a
 * page_cache_request_policy that denies the cache for those requests.
 *
 * These tests dispatch real requests through the http_kernel, so the whole
 * middleware stack, including page_cache, runs.
 *
 * Core's CommandLineOrUnsafeMethod policy denies every request when
 * PHP_SAPI is "cli", so under PHPUnit the page cache would never answer and
 * the tests would prove nothing. register() therefore swaps the default chain
 * for one that holds the same rules with the CLI check switched off. Policies
 * tagged page_cache_request_policy, DenySeamlessCookie included, are still
 * collected into it, and NoSessionOpen stays. The sanity test asserts that
 * both are present, and that the chain still denies a cookie request.
 *
 * @group drupal_seamless_cilogon
 */
class SeamlessCookiePageCacheTest extends KernelTestBase {

  const COOKIE = 'SESSaccesscisso';

  const PATH = '/seamless-cache-test';

  /**
   * {@inheritdoc}
   */
  protected static $modules = [
    'system',
    'user',
    'file',
    'options',
    'domain',
    'page_cache',
    'openid_connect',
    'openid_connect_cilogon_client',
    'drupal_seamless_cilogon',
    'seamless_cache_test',
  ];

  /**
   * {@inheritdoc}
   */
  public function register(ContainerBuilder $container) {
    parent::register($container);
    $container->register('page_cache_request_policy', CliAwareRequestPolicy::class)
      ->addArgument(new Reference('session_configuration'))
      ->addTag('service_collector', [
        'tag' => 'page_cache_request_policy',
        'call' => 'addPolicy',
      ])
      ->setPublic(TRUE);
  }

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->installEntitySchema('user');
    $this->installEntitySchema('domain');
    $this->installSchema('user', ['users_data']);
    $this->installConfig(['system', 'user', 'openid_connect', 'openid_connect_cilogon_client']);

    $this->config('system.performance')->set('cache.page.max_age', 21600)->save();
    $this->config('openid_connect.settings.cilogon')
      ->set('settings.client_id', 'test-client')
      ->set('settings.client_secret', 'test-secret')
      ->save();
    $this->container->get('state')
      ->set('drupal_seamless_cilogon.seamless_login_enabled', TRUE);

    // Html::getClass('ACCESS Support') is "access-support", which is what the
    // subscriber's domain check looks for.
    Domain::create([
      'id' => 'amp_cyberinfrastructure_org',
      'hostname' => 'support.access-ci.org',
      'name' => 'ACCESS Support',
      'scheme' => 'http',
      'status' => 1,
      'weight' => 0,
      'is_default' => TRUE,
    ])->save();
    Domain::create([
      'id' => 'connectci_org',
      'hostname' => 'connectci.org',
      'name' => 'ConnectCI',
      'scheme' => 'http',
      'status' => 1,
      'weight' => 1,
      'is_default' => FALSE,
    ])->save();
  }

  /**
   * Dispatches a GET through the full http_kernel stack.
   *
   * @param string $host
   *   The request host.
   * @param bool $with_cookie
   *   Whether to send the seamless SSO cookie.
   */
  protected function get(string $host, bool $with_cookie = FALSE): Response {
    $request = Request::create('http://' . $host . self::PATH, 'GET', [], $with_cookie ? [self::COOKIE => 'x'] : []);
    // The subscriber and session policy need a session on the request.
    $request->setSession($this->container->get('session'));
    $response = $this->container->get('http_kernel')->handle($request);
    // Drop the request pushed by the kernel so the next one starts clean.
    $this->container->get('request_stack')->pop();
    return $response;
  }

  /**
   * Whether a response's Cache-Control permits a shared cache to store it.
   */
  protected function isPubliclyCacheable(Response $response): bool {
    $cc = $response->headers->get('Cache-Control') ?? '';
    return str_contains($cc, 'public') && $response->headers->hasCacheControlDirective('max-age') && (int) $response->headers->getCacheControlDirective('max-age') > 0;
  }

  /**
   * The policy chain still contains the module's policy, and it still denies.
   *
   * Without this, overriding the CLI rule could silently hide a broken wiring.
   */
  public function testChainKeepsSeamlessPolicyAndSessionRule(): void {
    $chain = $this->container->get('page_cache_request_policy');
    $rules = (new \ReflectionProperty(ChainRequestPolicy::class, 'rules'))->getValue($chain);
    $this->assertNotEmpty(array_filter($rules, static fn($r) => $r instanceof DenySeamlessCookie), 'DenySeamlessCookie is in the chain.');
    $this->assertNotEmpty(array_filter($rules, static fn($r) => $r instanceof NoSessionOpen), 'NoSessionOpen is in the chain.');
    $this->assertEmpty(array_filter($rules, static fn($r) => $r instanceof CommandLineOrUnsafeMethod && !($r instanceof NonCliUnsafeMethod)), 'Core CLI rule is replaced.');
    $this->assertSame(RequestPolicyInterface::DENY, $chain->check(Request::create('http://support.access-ci.org/', 'GET', [], [self::COOKIE => 'x'])));
  }

  /**
   * Without the cookie, the page cache serves and marks pages as public.
   *
   * Regression guard: the fix must not turn page caching off for everyone.
   */
  public function testAnonymousWithoutCookieIsCached(): void {
    $first = $this->get('support.access-ci.org');
    $this->assertSame(200, $first->getStatusCode());
    $this->assertNotSame('HIT', $first->headers->get('X-Drupal-Cache'), 'First request is a miss.');

    $second = $this->get('support.access-ci.org');
    $this->assertSame(200, $second->getStatusCode());
    $this->assertSame('HIT', $second->headers->get('X-Drupal-Cache'));
    $this->assertTrue($this->isPubliclyCacheable($second), 'Cache-Control is public with a positive max-age: ' . $second->headers->get('Cache-Control'));
  }

  /**
   * A cookie holder on the ACCESS domain is redirected despite a cached page.
   */
  public function testCookieOnAccessDomainRedirectsToCilogon(): void {
    $this->get('support.access-ci.org');
    $this->assertSame('HIT', $this->get('support.access-ci.org')->headers->get('X-Drupal-Cache'), 'The page is cached before the cookie request.');

    $response = $this->get('support.access-ci.org', TRUE);
    $this->assertSame(302, $response->getStatusCode());
    $location = parse_url($response->headers->get('Location'));
    $this->assertSame('cilogon.org', $location['host']);
    $this->assertSame('/authorize', $location['path']);
    $this->assertNotSame('HIT', $response->headers->get('X-Drupal-Cache'));
    $this->assertFalse($this->isPubliclyCacheable($response), 'The redirect is not publicly cacheable: ' . $response->headers->get('Cache-Control'));
    // FinishResponseSubscriber reads the same policy chain, so the denial
    // replaces the subscriber's "public, max-age=0" with no-cache. That keeps
    // the edge from storing one user's CILogon redirect for everyone.
    $this->assertTrue($response->headers->hasCacheControlDirective('no-cache'), 'The redirect is marked no-cache: ' . $response->headers->get('Cache-Control'));

    // The redirect must not have replaced the cached page.
    $after = $this->get('support.access-ci.org');
    $this->assertSame(200, $after->getStatusCode());
    $this->assertSame('HIT', $after->headers->get('X-Drupal-Cache'));
  }

  /**
   * A cookie holder on another domain just gets the page.
   */
  public function testCookieOnOtherDomainGetsThePage(): void {
    $this->get('connectci.org');
    $this->assertSame('HIT', $this->get('connectci.org')->headers->get('X-Drupal-Cache'), 'The page is cached before the cookie request.');

    $response = $this->get('connectci.org', TRUE);
    $this->assertSame(200, $response->getStatusCode());
    $this->assertFalse($response->isRedirection());
    $this->assertStringContainsString('seamless cache test page', $response->getContent());
  }

}

/**
 * Core's CommandLineOrUnsafeMethod rule without the PHP_SAPI check.
 */
class NonCliUnsafeMethod extends CommandLineOrUnsafeMethod {

  /**
   * {@inheritdoc}
   */
  protected function isCli() {
    return FALSE;
  }

}

/**
 * The default page cache request policy, minus the CLI denial.
 */
class CliAwareRequestPolicy extends ChainRequestPolicy {

  /**
   * Constructs the policy.
   */
  public function __construct(SessionConfigurationInterface $session_configuration) {
    $this->addPolicy(new NonCliUnsafeMethod());
    $this->addPolicy(new NoSessionOpen($session_configuration));
  }

}
