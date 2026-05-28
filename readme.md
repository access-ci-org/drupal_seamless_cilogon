Readme for drupal seamless login.
See https://cyberteamportal.atlassian.net/browse/D8-1201 for more

One note for testers: if using seamless login on localhost, must first go to
/admin/services/drupal_seamless_cilogon and update the cookie domain to
'localhost' before swiching to asp domain -- or can never login (or get to
admin page).

This is set in a state variable named 'drupal_seamless_cilogon_cookie_domain'
and can be set via drush with:
drush state:set drupal_seamless_cilogon_cookie_domain 'localhost'

You can substitute a terminus command if it's on pantheon.
