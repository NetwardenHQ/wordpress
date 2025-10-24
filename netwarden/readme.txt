=== Netwarden ===
Contributors: netwardenhq
Tags: monitoring, uptime, performance, security, health-check
Requires at least: 5.8
Tested up to: 6.8
Requires PHP: 7.4
Stable tag: 1.0.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Enterprise-grade monitoring with predictive alerts, automated recommendations, and health scoring. Know about problems BEFORE they impact your site.

== Description ==

Netwarden is a lightweight, enterprise-grade monitoring plugin that helps you keep your WordPress site healthy, secure, and performant. Monitor critical metrics in real-time and receive alerts before issues impact your visitors.

= Key Features =

**🤖 Predictive Intelligence & Automation**
* Predictive disk space exhaustion alerts (30-60 days ahead using linear regression)
* Database growth trend analysis with alerts for rapid growth
* Overall health score (0-100 with letter grades A-F)
* Automated recommendations engine with 8+ actionable insights
* Proactive monitoring - catch issues BEFORE they happen

**🔐 Security Monitoring**
* Failed login attempt tracking (24-hour window)
* SSL certificate expiry monitoring with alerts
* Admin user count tracking for security audits
* WordPress core file integrity checks
* Brute force attack detection

**📊 Database & Performance**
* Database latency and connection status monitoring
* Database size tracking with growth predictions
* Disk usage monitoring (total, used, free, percentage)
* PHP memory usage tracking and limits
* Page load time sampling
* Database query performance tracking
* Slow query detection (>1 second queries)

**🔄 WordPress Updates**
* WordPress core update detection
* Plugin update tracking with premium plugin support
* Theme update tracking
* Security update identification

**👥 User Activity Monitoring**
* Total user count tracking
* Active users monitoring (7-day window)
* User role distribution (admin, editor, author, contributor, subscriber)
* Last login timestamp tracking

**🏥 Site Health Integration**
* WordPress Site Health API integration
* Health score tracking (0-100 scale)
* Critical issues detection
* Recommended improvements tracking

**🔌 Plugin Integrations**
* **WooCommerce**: Sales tracking, order counts, product inventory, stock alerts
* **Yoast SEO**: Average SEO score monitoring
* **UpdraftPlus**: Backup staleness monitoring
* **Contact Form 7**: Active forms tracking

**💡 Automated Recommendations**
* Performance recommendations (plugin count, slow queries, memory usage)
* Security recommendations (failed logins, admin accounts, unused themes)
* Maintenance recommendations (pending updates, backup staleness)
* E-commerce recommendations (WooCommerce out-of-stock alerts)
* Capacity recommendations (disk space warnings, cleanup suggestions)

= Why Choose Netwarden? =

* **Lightweight**: <1% CPU overhead - won't slow down your site
* **Secure**: Encrypted API communication, no third-party data sharing
* **Privacy-First**: Your data stays on YOUR infrastructure
* **WordPress Standards**: Follows WordPress coding standards and best practices
* **Real-Time Monitoring**: Minute-by-minute metric collection
* **Predictive**: Know about issues 30-60 days before they become critical

= Perfect For =

* Individual site owners who want peace of mind
* WordPress agencies managing multiple client sites
* E-commerce sites running WooCommerce
* Privacy-conscious organizations (GDPR/CCPA compliant)
* Mission-critical WordPress installations

== Installation ==

1. Upload the `netwarden` folder to `/wp-content/plugins/`
2. Activate the plugin through the 'Plugins' menu in WordPress
3. Navigate to **Settings > Netwarden** to configure
4. Get your free API key from [netwarden.com](https://netwarden.com)
5. Enter your Tenant ID and API Key
6. Click "Test Connection" to verify setup

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

Yes, this plugin requires a Netwarden account and sends monitoring data to https://app.netwarden.com/agent. All communication is encrypted via HTTPS. This is required for the plugin to function. See our Privacy Policy at https://netwarden.com/privacy for details.

= How often are metrics collected? =

Metrics are collected every minute via WP-Cron for real-time monitoring.

= What metrics are collected? =

The plugin collects: database health metrics (latency, size, connection status), disk usage statistics, WordPress version information, update availability (core, plugins, themes), security metrics (failed logins, SSL status, file integrity), performance metrics (PHP memory, page load time, query counts), user activity, and plugin-specific data (WooCommerce, Yoast SEO, etc.). No personal user data is collected.

== Screenshots ==

1. Admin settings page - Simple configuration with API key setup
2. Netwarden dashboard - View all your metrics in one place
3. Security metrics - Monitor failed logins, SSL expiry, file integrity
4. WordPress updates tracking - Stay on top of core, plugin, and theme updates

== Changelog ==

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
