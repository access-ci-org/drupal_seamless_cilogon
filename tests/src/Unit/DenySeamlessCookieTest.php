<?php

namespace Drupal\Tests\drupal_seamless_cilogon\Unit;

use Drupal\Core\PageCache\RequestPolicyInterface;
use Drupal\drupal_seamless_cilogon\PageCache\DenySeamlessCookie;
use Drupal\Tests\UnitTestCase;
use Symfony\Component\HttpFoundation\Request;

/**
 * Tests the page cache policy that denies requests with the SSO cookie.
 *
 * @coversDefaultClass \Drupal\drupal_seamless_cilogon\PageCache\DenySeamlessCookie
 *
 * @group drupal_seamless_cilogon
 */
class DenySeamlessCookieTest extends UnitTestCase {

  /**
   * Denies delivery when the seamless SSO cookie is present.
   *
   * @covers ::check
   */
  public function testDeniesWhenSeamlessCookieIsPresent(): void {
    $policy = new DenySeamlessCookie();
    $request = new Request([], [], [], ['SESSaccesscisso' => 'x']);

    $this->assertSame(RequestPolicyInterface::DENY, $policy->check($request));
  }

  /**
   * Denies delivery when the seamless SSO cookie has an empty value.
   *
   * @covers ::check
   */
  public function testDeniesWhenSeamlessCookieValueIsEmpty(): void {
    $policy = new DenySeamlessCookie();
    $request = new Request([], [], [], ['SESSaccesscisso' => '']);

    $this->assertSame(RequestPolicyInterface::DENY, $policy->check($request));
  }

  /**
   * Returns NULL, leaving the decision to other policies, with no cookies.
   *
   * @covers ::check
   */
  public function testReturnsNullWithoutCookies(): void {
    $policy = new DenySeamlessCookie();

    $this->assertNull($policy->check(new Request()));
  }

  /**
   * Returns NULL when only an unrelated Drupal session cookie is present.
   *
   * @covers ::check
   */
  public function testReturnsNullForUnrelatedSessionCookie(): void {
    $policy = new DenySeamlessCookie();
    $request = new Request([], [], [], ['SSESS0123456789abcdef0123456789abcdef' => 'x']);

    $this->assertNull($policy->check($request));
  }

}
