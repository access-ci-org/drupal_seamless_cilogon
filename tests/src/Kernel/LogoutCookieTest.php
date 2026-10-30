<?php

namespace Drupal\Tests\drupal_seamless_cilogon\Kernel;

use Drupal\Core\Routing\RouteMatchInterface;
use Drupal\KernelTests\KernelTestBase;
use Drupal\drupal_seamless_cilogon\EventSubscriber\DrupalSeamlessCilogonEventSubscriber;
use Drupal\Core\Session\AnonymousUserSession;
use Drupal\Core\Session\UserSession;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;

/**
 * What a logout leaves behind in the browser (D8-2896).
 *
 * This module decides who is logged in, on every request, and had no tests at
 * all — which is how two logout defects sat here unnoticed: the identity
 * cookie was never expired, and the response was marked publicly cacheable
 * while carrying Set-Cookie deletions.
 *
 * A kernel test rather than a unit test so user_logout() is a real function
 * rather than a stub; the subscriber calls it unqualified.
 *
 * @group drupal_seamless_cilogon
 */
class LogoutCookieTest extends KernelTestBase {

  const JWT_COOKIE = 'SESSaccess_auth';

  /**
   * The request from the last dispatch, for asserting its attributes.
   *
   * @var \Symfony\Component\HttpFoundation\Request|null
   */
  protected ?Request $lastRequest = NULL;
  const SSO_COOKIE = 'SESSaccesscisso';

  /**
   * {@inheritdoc}
   */
  protected static $modules = [
    'system',
    'user',
    'file',
    // The subscriber's constructor takes two openid_connect services, so the
    // container cannot build it without them.
    'openid_connect',
    'openid_connect_cilogon_client',
    'drupal_seamless_cilogon',
  ];

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->installEntitySchema('user');
    $this->installSchema('user', ['users_data']);
    $this->installConfig(['user']);

    // Seamless only acts when enabled; the domain gate passes because the
    // domain module is absent here, which is the production-equivalent path.
    $this->container->get('state')
      ->set('drupal_seamless_cilogon.seamless_login_enabled', 1);
    $this->container->get('state')
      ->set('drupal_seamless_cilogon.seamless_cookie_domain', '.access-ci.org');
  }

  /**
   * Dispatches onRequest and returns whatever response it set.
   *
   * @param string $route
   *   The matched route name.
   * @param bool $authenticated
   *   Whether the current user is authenticated.
   * @param array<string, string> $cookies
   *   Cookies the browser sends.
   * @param string $path
   *   The request path.
   * @param string $class
   *   The subscriber class, so a test can observe a protected step.
   */
  protected function dispatch(string $route, bool $authenticated, array $cookies, string $path = '/user/logout', string $class = DrupalSeamlessCilogonEventSubscriber::class): ?Response {
    $this->container->get('current_user')->setAccount($authenticated
      ? new UserSession(['uid' => 2, 'name' => 'someone', 'roles' => ['authenticated']])
      : new AnonymousUserSession());

    $request = Request::create('https://support.access-ci.org' . $path);
    foreach ($cookies as $name => $value) {
      $request->cookies->set($name, $value);
    }
    // The subscriber reads a session flag; give the request a real one.
    $request->setSession(new Session(new MockArraySessionStorage()));
    $this->container->get('request_stack')->push($request);
    $this->lastRequest = $request;

    // The subscriber reads the route from the route_match service, not from
    // the request attributes, so the route has to be injected rather than set
    // on the request.
    $route_match = $this->createMock(RouteMatchInterface::class);
    $route_match->method('getRouteName')->willReturn($route);

    $subscriber = new $class(
      $this->container->get('state'),
      $this->container->get('config.factory'),
      $this->container->get('current_user'),
      $route_match,
      $this->container->get('logger.factory'),
      $this->container->get('request_stack'),
      $this->container->get('messenger'),
      $this->container->get('token'),
      $this->container->get('module_handler'),
      $this->container->get('session_manager'),
      $this->container->get('plugin.manager.openid_connect_client'),
      $this->container->get('openid_connect.claims'),
      $this->container->get('page_cache_kill_switch'),
    );

    $event = new RequestEvent(
      $this->container->get('http_kernel'),
      $request,
      HttpKernelInterface::MAIN_REQUEST,
    );
    $subscriber->onRequest($event);

    return $event->getResponse();
  }

  /**
   * Every Set-Cookie of a given name on a response.
   *
   * Plural on purpose: an implementation clearing on one domain while setting
   * on another emits two, and reading only the first would call that a pass.
   *
   * @return array<int, \Symfony\Component\HttpFoundation\Cookie>
   *   The matching cookies.
   */
  protected function cookies(Response $response, string $name): array {
    return array_values(array_filter(
      $response->headers->getCookies(),
      static fn (Cookie $c): bool => $c->getName() === $name,
    ));
  }

  /**
   * Logout expires the identity cookie, not just the SSO marker.
   *
   * The defect: doDeleteCookie() expired SESSaccesscisso and left
   * SESSaccess_auth alone, so an 18-hour rolling identity token outlived the
   * logout and every site trusting it kept the user signed in.
   */
  public function testLogoutExpiresTheIdentityCookie(): void {
    $response = $this->dispatch('user.logout', TRUE, [
      self::SSO_COOKIE => '1',
      self::JWT_COOKIE => 'a-still-valid-token',
    ]);

    $this->assertNotNull($response, 'Logout produces a response.');

    $found = $this->cookies($response, self::SSO_COOKIE);
    $this->assertCount(1, $found, 'One Set-Cookie for the SSO marker.');
    $this->assertEmpty($found[0]->getValue(), 'The SSO marker is cleared.');
    $this->assertLessThan(time(), $found[0]->getExpiresTime());

    // The identity cookie is the access module's: this module asks for the
    // clear rather than emitting one, so its name, domain rules and
    // attributes stay in the module that owns them.
    $this->assertSame([], $this->cookies($response, self::JWT_COOKIE));
    $this->assertTrue(
      $this->lastRequest->attributes->get('access_force_logout'),
      'Logout asks the access module to clear its cookie.',
    );
  }

  /**
   * Logout is expired unconditionally, even if the browser withheld it.
   *
   * A cookie the browser holds but did not send is exactly the one that must
   * not survive logout.
   */
  public function testLogoutExpiresEvenWhenNotSent(): void {
    $response = $this->dispatch('user.logout', TRUE, []);

    $this->assertNotNull($response);
    $this->assertCount(1, $this->cookies($response, self::SSO_COOKIE));
    $this->assertTrue($this->lastRequest->attributes->get('access_force_logout'));
  }

  /**
   * The logout response is never shared-cacheable.
   *
   * It carries Set-Cookie deletions. Marked public, Drupal's internal page
   * cache stored and replayed it — verified in production as repeated
   * x-drupal-cache HITs with a frozen expires timestamp.
   */
  public function testLogoutResponseIsNotShareable(): void {
    $response = $this->dispatch('user.logout', TRUE, [
      self::SSO_COOKIE => '1',
      self::JWT_COOKIE => 'tok',
    ]);

    $cache_control = $response->headers->get('Cache-Control') ?? '';
    $this->assertStringNotContainsString('public', $cache_control);
    $this->assertStringContainsString('no-store', $cache_control);
  }

  /**
   * The safety logout ends a session, so it clears like any other logout.
   *
   * Authenticated on an ordinary route with the SSO cookie gone: the module
   * logs the user out there. It used to build its own redirect and expire
   * nothing, leaving the identity cookie live on a logout response.
   */
  public function testSafetyLogoutAlsoClearsBothCookies(): void {
    $response = $this->dispatch('entity.node.canonical', TRUE, [
      self::JWT_COOKIE => 'tok',
    ]);

    $this->assertNotNull($response, 'The safety logout produces a response.');
    $found = $this->cookies($response, self::SSO_COOKIE);
    $this->assertCount(1, $found, 'Safety logout expires the SSO marker.');
    $this->assertEmpty($found[0]->getValue());
    // The path no route list can reach, which is why the attribute exists.
    $this->assertTrue(
      $this->lastRequest->attributes->get('access_force_logout'),
      'The safety logout asks for the identity cookie to be cleared.',
    );
  }

  /**
   * An ordinary authenticated page is left alone.
   *
   * The logout handling is route-scoped; it must not disturb normal browsing,
   * which is what the rolling re-mint depends on.
   */
  public function testNormalPageIsUntouched(): void {
    $response = $this->dispatch('entity.node.canonical', TRUE, [
      self::SSO_COOKIE => '1',
      self::JWT_COOKIE => 'tok',
    ]);

    $this->assertNull($response, 'A normal page gets no interception.');
  }

  /**
   * The access token endpoints answer anonymous callers themselves.
   *
   * They are fetched by script, which cannot follow a redirect to CILogon, so
   * an anonymous request carrying the SSO cookie must reach the endpoint and
   * get its JSON login_required rather than a 302. Every other path still
   * redirects.
   *
   * @dataProvider tokenPathCases
   */
  public function testTokenEndpointsAreNotRedirected(string $path, bool $redirected): void {
    $response = $this->dispatch('some.route', FALSE, [self::SSO_COOKIE => '1'], $path, RedirectMarkingSubscriber::class);
    $this->assertSame($redirected, $response !== NULL && $response->headers->get('X-Test-Redirect') === 'cilogon');
  }

  public static function tokenPathCases(): array {
    return [
      'agent token' => ['/api/agent-token', FALSE],
      'token exchange' => ['/api/token-exchange', FALSE],
      'a prefix of the path is not exempt' => ['/api/agent-token/x', TRUE],
      'other api paths still redirect' => ['/api/2.2/events', TRUE],
      'pages still redirect' => ['/node/1', TRUE],
    ];
  }

}

/**
 * Records the CILogon redirect instead of running the OpenID flow.
 */
class RedirectMarkingSubscriber extends DrupalSeamlessCilogonEventSubscriber {

  /**
   * {@inheritdoc}
   */
  protected function doRedirectToCilogon(RequestEvent $event, bool $seamless_debug): void {
    $event->setResponse(new Response('', 302, ['X-Test-Redirect' => 'cilogon']));
  }

}
