=== Netwarden ===
Contributors: netwardenhq
Tags: monitoring, uptime, performance, security, health-check
Requires at least: 5.8
Tested up to: 6.9
Requires PHP: 7.4
Stable tag: 1.1.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Monitors your WordPress site's health, updates, security posture and performance, and sends the readings to your Netwarden dashboard every minute.

== Description ==

Netwarden is a lightweight monitoring plugin that reports your WordPress site's health, security posture and performance to the Netwarden platform, where you get dashboards, history and alerts. Every reading it sends is something it actually measured; when a value cannot be measured (a page that would not load, a certificate it could not read) it reports nothing rather than a zero.

= What it monitors =

**🔐 Security**
* Failed login attempts in the last 24 hours
* TLS certificate expiry (days remaining, issuer)
* Number of administrator accounts

**📊 Database & Performance**
* Database latency and connection status monitoring
* Database size tracking with growth predictions
* Disk usage monitoring (total, used, free, percentage)
* PHP memory usage tracking and limits
* Page load time sampling
* Database query performance tracking
* Slow query detection (>1 second queries)

**🔄 WordPress Updates**
* WordPress core update detection, distinguishing point releases (security and maintenance) from feature releases
* Plugin and theme updates pending, as WordPress itself reports them

**👥 User Activity Monitoring**
* Total user count tracking
* Active users monitoring (7-day window)
* User role distribution (admin, editor, author, contributor, subscriber)
* Last login timestamp tracking

**🏥 Health score and trends**
* A 0–100 health score with a letter grade, computed from the readings above (security, performance, pending updates, capacity, backups)
* Disk-space exhaustion forecast: once a week of hourly samples exists, a linear trend projects when the disk reaches 95%
* Database growth rate, when it exceeds 10 MB a day

**🔌 Plugin integrations** (only when the plugin is installed)
* **WooCommerce**: 30-day revenue from completed and processing orders, pending and processing order counts, published products, out-of-stock products — on both classic and High-Performance Order Storage
* **Yoast SEO**: average SEO score across posts
* **UpdraftPlus**: hours since the last backup
* **Contact Form 7**: number of published forms

= Why Netwarden =

* **Lightweight**: one WP-Cron event a minute; the expensive readings (database size, certificate, page load, user counts) are cached for minutes to hours
* **Honest**: a reading that could not be taken is absent, never a made-up zero
* **Secure**: HTTPS to the platform, credentials encrypted at rest with AES-256-GCM under your site's auth salt
* **Self-hosted friendly**: point it at your own Netwarden server

= Good for =

* Site owners who want to know before something breaks
* Agencies watching many client sites from one dashboard
* WooCommerce stores

== External Services ==

This plugin relies on external services to function properly. Below is a complete disclosure of all external services used:

= WordPress.org API =

**Purpose:** To check for available WordPress core updates and security releases.

**Service URL:** https://api.wordpress.org/core/version-check/1.7/

**Data Sent:** Only WordPress version information from your site (e.g., "6.8") is sent to check if updates are available. No personal data or site-specific information is transmitted.

**When Data is Sent:** Once every 12 hours when the plugin checks for WordPress updates. Results are cached to minimize API calls.

**Terms of Service:** https://wordpress.org/about/terms/
**Privacy Policy:** https://wordpress.org/about/privacy/

= Netwarden Monitoring API =

**Purpose:** To send monitoring metrics from your WordPress site to Netwarden's monitoring platform for visualization, alerting, and analysis.

**Service URL:** https://api.netwarden.com/agent/data

**Data Sent:**
* Database health metrics (latency, size, connection status)
* Disk usage statistics (total, used, free space)
* WordPress version information
* Plugin and theme update availability
* Security metrics (failed login counts, SSL certificate status, admin user count)
* Performance metrics (PHP memory usage, page load times, database query counts)
* User activity statistics (total users, active user counts, role distribution - NO personal identifying information)
* Site health scores
* Plugin-specific data if installed: WooCommerce (order/product counts, sales totals), Yoast SEO (average SEO scores), UpdraftPlus (backup status)

**Important:** No personal user data (names, emails, passwords, IP addresses, or content) is collected or transmitted.

**When Data is Sent:** Every minute via WordPress Cron (WP-Cron) after you configure your API credentials.

**Authentication:** Requires your unique Tenant ID and API Key (obtained from netwarden.com).

**Terms of Service:** https://netwarden.com/terms
**Privacy Policy:** https://netwarden.com/privacy

**Note:** This plugin REQUIRES a Netwarden account to function. The monitoring data is essential for the plugin's core functionality. Without transmitting this data to Netwarden's servers, the plugin cannot provide monitoring services.

== Installation ==

1. Upload the `netwarden` folder to `/wp-content/plugins/`
2. Activate the plugin through the 'Plugins' menu in WordPress
3. Open **Netwarden** in the admin menu
4. Get your Tenant ID and API key from [app.netwarden.com/settings/tokens](https://app.netwarden.com/settings/tokens)
5. Enter them and save
6. Click "Send Metrics Now" to confirm the connection

That's it! Metrics will begin collecting every minute automatically.

== Frequently Asked Questions ==

= Do I need a Netwarden account? =

Yes, Netwarden requires a free account to store and visualize your metrics. Sign up at [netwarden.com](https://netwarden.com).

= Does this work with Multisite? =

The plugin has limited Multisite support. For best results, install on individual WordPress sites.

= Will this slow down my site? =

No. Netwarden uses efficient caching and background processing to ensure <1% CPU overhead. All heavy operations are cached and run via WP-Cron.

= What if WP-Cron is disabled? =

If WP-Cron is disabled, you'll need to set up a system cron job. The plugin will show you the exact command to use.

= Is my data secure? =

Yes. All API communication is encrypted via HTTPS, and your data is stored securely on Netwarden's infrastructure. We never share your data with third parties.

= Does this plugin send data to external services? =

Yes, this plugin requires a Netwarden account and sends monitoring data to https://api.netwarden.com/agent/data (or to your own server if you configure one). All communication is encrypted via HTTPS. This is required for the plugin to function. See our Privacy Policy at https://netwarden.com/privacy for details.

= How often are metrics collected? =

Metrics are collected every minute via WP-Cron for real-time monitoring.

= What metrics are collected? =

The plugin collects: database health metrics (latency, size, connection status), disk usage statistics, WordPress version information, update availability (core, plugins, themes), security metrics (failed logins, TLS certificate expiry, administrator count), performance metrics (PHP memory, page load time, query counts), user activity counts, and plugin-specific data (WooCommerce, Yoast SEO, UpdraftPlus, Contact Form 7). No personal user data is collected.

== Screenshots ==

1. Admin settings page - Simple configuration with API key setup
2. Netwarden dashboard - View all your metrics in one place
3. Security metrics - Monitor failed logins, TLS expiry, administrator accounts
4. WordPress updates tracking - Stay on top of core, plugin, and theme updates

== Changelog ==

= 1.1.0 =
* Fixed: security-update detection was backwards — a new feature release was flagged as a security update and a pending point release (where WordPress ships security fixes) was not.
* Fixed: WooCommerce revenue and order counts read nothing on stores using High-Performance Order Storage (the default since WooCommerce 8.2) and reported $0 in sales. Revenue now counts completed and processing orders only.
* Fixed: the 24-hour failed-login count never expired unless another login failed.
* Fixed: the TLS certificate was never checked when WP-Cron ran from a system cron or WP-CLI.
* Fixed: a homepage that failed to load was reported as a 0 ms page load; a health score that could not be computed was reported as 50 (C). Both are now simply absent.
* Fixed: WP-Cron self-heal ran on every front-end request; it now runs on admin and cron requests only.
* Fixed: the admin script was loaded twice on the settings page.
* Fixed: uninstall left options, transients and user meta behind.
* Changed: trend history is sampled hourly instead of every minute — the option it lives in was growing to ~1.7 MB and being rewritten on every run. Forecasts now require a week of data by time span rather than by sample count.
* Changed: user counts come from WordPress's aggregate query instead of loading every user; the plugin's heaviest query on large membership sites is gone.
* Changed: credentials are stored with AES-256-GCM (authenticated); existing entries are read and rewritten on the next save.
* Changed: the plugin identifies itself with a User-Agent, sends latency only once it has measured one, and no longer guesses the host's Linux distribution.
* Removed from the description: claims of core file integrity checks, brute-force detection, Site Health integration and a recommendations engine, none of which the plugin implemented.

= 1.0.0 =
* Initial public release
* Database health monitoring (latency, size, connection status)
* Disk usage monitoring with predictive exhaustion alerts
* WordPress update tracking (core, plugins, themes)
* Security monitoring (failed logins, SSL expiry, file integrity, admin accounts)
* Performance tracking (PHP memory, page load time, query performance)
* User activity monitoring (total users, active users, role distribution)
* WordPress Site Health integration
* Plugin integrations (WooCommerce, Yoast SEO, UpdraftPlus, Contact Form 7)
* Automated recommendations engine (8+ recommendation rules)
* Health score calculation (0-100 with letter grades)
* Predictive analytics (disk exhaustion, database growth trends)
* Real-time minute-by-minute metric collection
* WP-Cron integration for background processing

== Upgrade Notice ==

= 1.0.0 =
Initial release of Netwarden - Enterprise-grade WordPress monitoring with predictive alerts, automated recommendations, and comprehensive health tracking. Get insights into your site's health before problems become critical.

== Support ==

For support, please visit [netwarden.com/support](https://netwarden.com/support) or email support@netwarden.com.

== Privacy Policy ==

Netwarden collects the following data from your WordPress site:
* Database health metrics (latency, size, connection status)
* Disk usage statistics
* WordPress version information
* Update availability (core, plugins, themes)
* Security metrics (failed logins, SSL status, file integrity)
* Performance metrics (PHP memory, page load time, query counts)
* User activity (total count, active users, role distribution - no personal data)
* Plugin health status
* WooCommerce data (if installed): sales totals, order counts, product counts
* SEO scores (if Yoast SEO installed)
* Backup status (if UpdraftPlus installed)

This data is transmitted securely via HTTPS to Netwarden's servers (https://app.netwarden.com/agent) and used solely for monitoring purposes. We do not collect or store personal user information (names, emails, passwords, etc.). We do not share your data with third parties.

For more information, see our full privacy policy at https://netwarden.com/privacy.
