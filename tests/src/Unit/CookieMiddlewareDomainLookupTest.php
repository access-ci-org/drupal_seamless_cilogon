<?php

namespace Drupal\Tests\drupal_seamless_cilogon\Unit;

use Drupal\Core\Entity\EntityStorageInterface;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Extension\ModuleHandlerInterface;
use Drupal\Core\Logger\LoggerChannelFactoryInterface;
use Drupal\Core\Logger\LoggerChannelInterface;
use Drupal\Core\State\StateInterface;
use Drupal\Tests\UnitTestCase;
use Drupal\drupal_seamless_cilogon\StackMiddleware\CookieMiddleware;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\HttpKernelInterface;

/**
 * The middleware's domain lookup on a cold entity type cache (D8-2921).
 *
 * The middleware runs before kernel_pre_handle loads the .module files. On
 * Drupal 11, rebuilding the entity type definitions at that point throws,
 * and an uncaught throw here failed every request until drush rebuilt them.
 *
 * @group drupal_seamless_cilogon
 */
class CookieMiddlewareDomainLookupTest extends UnitTestCase {

  /**
   * The inner kernel's response, to assert the request was passed through.
   */
  protected Response $innerResponse;

  /**
   * Builds the middleware with a domain storage lookup we control.
   *
   * @param callable $get_storage
   *   Called in place of EntityTypeManager::getStorage('domain').
   * @param \Drupal\Core\Logger\LoggerChannelInterface|null $logger
   *   The logger channel, or NULL for a mock that accepts anything.
   */
  protected function buildMiddleware(callable $get_storage, ?LoggerChannelInterface $logger = NULL): CookieMiddleware {
    $this->innerResponse = new Response('inner');
    $kernel = $this->createMock(HttpKernelInterface::class);
    $kernel->method('handle')->willReturn($this->innerResponse);

    $logger ??= $this->createMock(LoggerChannelInterface::class);
    $logger_factory = $this->createMock(LoggerChannelFactoryInterface::class);
    $logger_factory->method('get')->willReturn($logger);

    $state = $this->createMock(StateInterface::class);
    $state->method('get')->willReturnCallback(
      fn ($key, $default = NULL) => $key === 'drupal_seamless_cilogon.seamless_login_enabled' ? TRUE : $default
    );

    $module_handler = $this->createMock(ModuleHandlerInterface::class);
    $module_handler->method('moduleExists')->willReturnMap([
      ['domain', TRUE],
      ['openid_connect_cilogon_client', TRUE],
    ]);

    $entity_type_manager = $this->createMock(EntityTypeManagerInterface::class);
    $entity_type_manager->method('getStorage')->with('domain')->willReturnCallback($get_storage);

    return new CookieMiddleware($kernel, $logger_factory, $state, $module_handler, $entity_type_manager);
  }

  /**
   * A request from a returning CILogon user, which would normally redirect.
   */
  protected function ssoRequest(): Request {
    return Request::create('/events', 'GET', [], ['SESSaccesscisso' => '1']);
  }

  /**
   * A domain lookup that throws passes the request through instead of failing.
   */
  public function testDomainLookupThatThrowsPassesThrough(): void {
    $logger = $this->createMock(LoggerChannelInterface::class);
    $logger->expects($this->once())->method('warning');

    $middleware = $this->buildMiddleware(function () {
      throw new \InvalidArgumentException('Class "access_misc_entity_type_build" does not exist.');
    }, $logger);

    $response = $middleware->handle($this->ssoRequest());

    $this->assertSame($this->innerResponse, $response);
  }

  /**
   * On the ACCESS domain the seamless redirect still happens.
   */
  public function testAccessDomainStillRedirects(): void {
    $middleware = $this->buildMiddleware(function () {
      $storage = $this->getMockBuilder(EntityStorageInterface::class)
        ->addMethods(['loadDefaultId'])
        ->getMockForAbstractClass();
      $storage->method('loadDefaultId')->willReturn('amp_cyberinfrastructure_org');
      return $storage;
    });

    $response = $middleware->handle($this->ssoRequest());

    $this->assertInstanceOf(RedirectResponse::class, $response);
    $this->assertSame('/user/login?redirect=%2Fevents', $response->getTargetUrl());
  }

}
