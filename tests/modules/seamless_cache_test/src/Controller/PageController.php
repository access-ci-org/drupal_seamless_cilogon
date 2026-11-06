<?php

namespace Drupal\seamless_cache_test\Controller;

use Drupal\Core\Cache\CacheableResponse;

/**
 * Returns a minimal cacheable response, with no theme or render pipeline.
 */
class PageController {

  /**
   * Builds the response.
   */
  public function build(): CacheableResponse {
    return new CacheableResponse('seamless cache test page', 200, ['Content-Type' => 'text/html']);
  }

}
