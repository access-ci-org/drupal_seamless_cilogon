<?php

namespace Drupal\drupal_seamless_cilogon\Controller;

use Drupal\Core\Controller\ControllerBase;
use Drupal\Core\PageCache\ResponsePolicy\KillSwitch;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Drupal\Core\Url;

/**
 * Controller for Match.
 */
class NcController extends ControllerBase {

  /**
   * Page cache kill switch.
   *
   * @var \Drupal\Core\PageCache\ResponsePolicy\KillSwitch
   */
  protected $killSwitch;

  /**
   * {@inheritdoc}
   */
  public function __construct(KillSwitch $kill_switch) {
    $this->killSwitch = $kill_switch;
  }

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container): static {
    // @phpstan-ignore-next-line
    return new static(
      $container->get('page_cache_kill_switch')
    );
  }

  /**
   * Build content to display on page.
   *
   * @return array<string, mixed>
   *   Render array.
   */
  public function noCache(): array {
    $this->killSwitch->trigger();
    $url = Url::fromRoute('<front>', [], ['absolute' => 'true'])->toString();
    $home = new RedirectResponse($url);
    $home->send();
    return [
      '#markup' => '<p>Redirecting to home page</p>',
    ];
  }

}
