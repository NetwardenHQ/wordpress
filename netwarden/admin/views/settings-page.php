<?php
/**
 * Admin Settings Page View
 */

// Exit if accessed directly
if (!defined('ABSPATH')) {
    exit;
}
?>

<div class="wrap netwarden-settings">
    <!-- Custom header with bigger logo -->
    <div class="netwarden-header">
        <div class="netwarden-header-content">
            <img src="<?php echo esc_url(NETWARDEN_PLUGIN_URL . 'images/netwarden-logo.png'); ?>"
                 alt="<?php esc_attr_e('Netwarden', 'netwarden'); ?>"
                 class="netwarden-logo">
            <span class="netwarden-version">v<?php echo esc_html(NETWARDEN_VERSION); ?></span>
        </div>
    </div>

    <!-- WordPress default h1 (hidden via CSS) -->
    <h1></h1>

    <?php if ($show_welcome): ?>
        <div class="netwarden-welcome-card">
            <h2><?php esc_html_e('Welcome to Netwarden!', 'netwarden'); ?></h2>
            <p>
                <?php esc_html_e('Netwarden is an enterprise-grade infrastructure monitoring platform that helps you keep track of your WordPress site\'s health, performance, and security. Monitor database performance, disk usage, system updates, and more - all from a centralized dashboard.', 'netwarden'); ?>
            </p>
            <p>
                <strong><?php esc_html_e('To get started, you\'ll need your Netwarden credentials:', 'netwarden'); ?></strong>
            </p>
            <ol>
                <li><?php
                    printf(
                        /* translators: %s: Link to Netwarden signup page with HTML anchor tag */
                        esc_html__('Sign up for a Netwarden account at %s', 'netwarden'),
                        sprintf('<a href="%s" target="_blank">%s</a>', esc_url('https://app.netwarden.com'), esc_html('app.netwarden.com'))
                    );
                ?></li>
                <li><?php
                    printf(
                        /* translators: %s: Link to agent tokens settings page with HTML anchor tag */
                        esc_html__('Go to %s', 'netwarden'),
                        sprintf('<a href="%s" target="_blank">%s</a>', esc_url('https://app.netwarden.com/settings/tokens'), esc_html__('Settings → Agent Tokens', 'netwarden'))
                    );
                ?></li>
                <li><?php
                    printf(
                        /* translators: %1$s: Bold "Tenant ID" label in HTML strong tags, %2$s: Bold "API Key" label in HTML strong tags */
                        esc_html__('Create a new agent token and copy your %1$s and %2$s', 'netwarden'),
                        sprintf('<strong>%s</strong>', esc_html__('Tenant ID', 'netwarden')),
                        sprintf('<strong>%s</strong>', esc_html__('API Key', 'netwarden'))
                    );
                ?></li>
                <li><?php esc_html_e('Enter your credentials below to start monitoring', 'netwarden'); ?></li>
            </ol>
        </div>
    <?php endif; ?>

    <div class="netwarden-card">
        <h2><?php esc_html_e('Configuration', 'netwarden'); ?></h2>

        <?php if ($is_configured): ?>
            <div class="netwarden-status">
                <div class="status-item">
                    <span class="status-label"><?php esc_html_e('Status:', 'netwarden'); ?></span>
                    <span class="status-value status-active">
                        <span class="status-indicator"></span> <?php esc_html_e('Active', 'netwarden'); ?>
                    </span>
                </div>
                <div class="status-item">
                    <span class="status-label"><?php esc_html_e('Tenant ID:', 'netwarden'); ?></span>
                    <span class="status-value"><?php echo esc_html($credentials['tenant_id']); ?></span>
                </div>
                <?php if ($last_submission): ?>
                    <div class="status-item">
                        <span class="status-label"><?php esc_html_e('Last Metric Submission:', 'netwarden'); ?></span>
                        <span class="status-value"><?php
                            /* translators: %s: Human-readable time difference (e.g., "5 minutes") */
                            echo sprintf(esc_html__('%s ago', 'netwarden'), esc_html(human_time_diff($last_submission, time())));
                        ?></span>
                    </div>
                <?php endif; ?>
                <?php
                $next_cron = wp_next_scheduled('netwarden_collect_metrics');
                $cron_enabled = !defined('DISABLE_WP_CRON') || !DISABLE_WP_CRON;
                ?>
                <div class="status-item">
                    <span class="status-label"><?php esc_html_e('Cron Status:', 'netwarden'); ?></span>
                    <span class="status-value">
                        <?php if ($cron_enabled && $next_cron): ?>
                            <?php
                            // Check if cron is actually working (submitted in last 2 minutes)
                            $cron_is_working = $last_submission && (time() - $last_submission) <= 120;

                            $time_until = $next_cron - time();

                            // If metrics submitted recently, show friendly message instead of "overdue"
                            if ($cron_is_working && $time_until < 0) {
                                $time_display = esc_html__('soon', 'netwarden');
                            } elseif ($time_until > 0) {
                                if ($time_until < 120) {
                                    /* translators: %s: Number of seconds */
                                    $time_display = sprintf(esc_html(_n('%s second', '%s seconds', $time_until, 'netwarden')), number_format_i18n($time_until));
                                } else {
                                    $time_display = esc_html(human_time_diff(time(), $next_cron));
                                }
                            } else {
                                /* translators: %s: Number of seconds ago */
                                $time_display = sprintf(esc_html__('overdue (%ss ago)', 'netwarden'), number_format_i18n(abs($time_until)));
                            }
                            ?>
                            <?php if (!$cron_is_working && $last_submission && $time_until < -300): ?>
                                <span style="color: #dc3232;"><?php esc_html_e('Stopped', 'netwarden'); ?></span> <?php
                                    /* translators: %s: Human-readable time difference (e.g., "10 minutes") */
                                    echo sprintf(esc_html__('(last submission %s ago)', 'netwarden'), esc_html(human_time_diff($last_submission, time())));
                                ?>
                            <?php else: ?>
                                <span style="color: #46b450;"><?php esc_html_e('Scheduled', 'netwarden'); ?></span> <?php
                                    // translators: %s: Time until next cron run (e.g., "30 seconds", "5 minutes")
                                    echo sprintf(esc_html__('(next run in %s)', 'netwarden'), esc_html($time_display));
                                ?>
                            <?php endif; ?>
                        <?php elseif (!$cron_enabled): ?>
                            <span style="color: #dc3232;"><?php esc_html_e('WP-Cron Disabled', 'netwarden'); ?></span>
                        <?php else: ?>
                            <span style="color: #ffb900;"><?php esc_html_e('Not Scheduled', 'netwarden'); ?></span>
                        <?php endif; ?>
                    </span>
                </div>
            </div>

            <div class="netwarden-actions">
                <button type="button" id="netwarden-test-btn" class="button button-secondary">
                    <?php esc_html_e('Send Metrics Now', 'netwarden'); ?>
                </button>
                <button type="button" id="netwarden-delete-btn" class="button button-link-delete">
                    <?php esc_html_e('Delete Credentials', 'netwarden'); ?>
                </button>
            </div>
        <?php else: ?>
            <p>
                <?php
                printf(
                    /* translators: %s: Link to Netwarden agent tokens page with HTML anchor tag */
                    esc_html__('Enter your Netwarden credentials to start monitoring. Get your credentials from %s', 'netwarden'),
                    sprintf('<a href="%s" target="_blank">%s</a>', esc_url('https://app.netwarden.com/settings/tokens'), esc_html('app.netwarden.com/settings/tokens'))
                );
                ?>
            </p>

            <form id="netwarden-credentials-form">
                <table class="form-table">
                    <tr>
                        <th scope="row">
                            <label for="netwarden_tenant_id"><?php esc_html_e('Tenant ID', 'netwarden'); ?></label>
                        </th>
                        <td>
                            <input type="text"
                                   id="netwarden_tenant_id"
                                   name="tenant_id"
                                   class="regular-text"
                                   maxlength="10"
                                   pattern="[a-zA-Z0-9]{10}"
                                   required>
                            <p class="description"><?php esc_html_e('10 alphanumeric characters', 'netwarden'); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">
                            <label for="netwarden_api_key"><?php esc_html_e('API Key', 'netwarden'); ?></label>
                        </th>
                        <td>
                            <input type="password"
                                   id="netwarden_api_key"
                                   name="api_key"
                                   class="regular-text"
                                   pattern="nw_sk_.*"
                                   required>
                            <p class="description"><?php esc_html_e('Starts with \'nw_sk_\'', 'netwarden'); ?></p>
                        </td>
                    </tr>
                </table>

                <p class="submit">
                    <button type="submit" class="button button-primary" id="netwarden-save-btn">
                        <?php esc_html_e('Save Credentials', 'netwarden'); ?>
                    </button>
                </p>
            </form>
        <?php endif; ?>

        <div id="netwarden-message" class="netwarden-message" style="display: none;"></div>
    </div>

    <div class="netwarden-card">
        <h2><?php esc_html_e('Monitored Metrics', 'netwarden'); ?></h2>
        <p><?php esc_html_e('The Netwarden plugin automatically collects and sends the following metrics:', 'netwarden'); ?></p>
        <ul class="netwarden-metrics-list">
            <li><strong><?php esc_html_e('Database Health:', 'netwarden'); ?></strong> <?php esc_html_e('Connection status, query response time, database size', 'netwarden'); ?></li>
            <li><strong><?php esc_html_e('Disk Usage:', 'netwarden'); ?></strong> <?php esc_html_e('Total disk space, used space, free space, usage percentage', 'netwarden'); ?></li>
            <li><strong><?php esc_html_e('WordPress Updates:', 'netwarden'); ?></strong> <?php esc_html_e('Core updates available, plugin updates available, security updates', 'netwarden'); ?></li>
            <li><strong><?php esc_html_e('Agent Status:', 'netwarden'); ?></strong> <?php esc_html_e('Plugin status, API latency, WP-Cron status', 'netwarden'); ?></li>
        </ul>

        <?php if (class_exists('UpdraftPlus')): ?>
        <div style="margin-top: 20px; padding: 16px; background-color: #f0f9ff; border-left: 4px solid #3b82f6; border-radius: 4px;">
            <h3 style="margin: 0 0 8px 0; color: #1e40af; font-size: 16px;">
                <span style="display: inline-block; margin-right: 8px;">✓</span>
                <?php esc_html_e('UpdraftPlus Integration Detected', 'netwarden'); ?>
            </h3>
            <p style="margin: 0; color: #1e3a8a; line-height: 1.6;">
                <?php esc_html_e('Netwarden automatically monitors your UpdraftPlus backup status. We track when backups are performed and alert you if backups become stale or overdue, helping ensure your site data is always protected.', 'netwarden'); ?>
            </p>
            <p style="margin: 8px 0 0 0; color: #1e3a8a; line-height: 1.6;">
                <strong><?php esc_html_e('Monitored metrics:', 'netwarden'); ?></strong>
                <?php esc_html_e('Last backup timestamp, hours since last backup, backup schedule compliance', 'netwarden'); ?>
            </p>
        </div>
        <?php endif; ?>

        <p>
            <?php
            printf(
                /* translators: %s: Link to Netwarden dashboard with HTML anchor tag */
                esc_html__('Metrics are collected automatically and sent to your Netwarden dashboard at %s. Collection frequency depends on your plan.', 'netwarden'),
                sprintf('<a href="%s" target="_blank">%s</a>', esc_url('https://app.netwarden.com'), esc_html('app.netwarden.com'))
            );
            ?>
        </p>
    </div>

    <div class="netwarden-card">
        <h2><?php esc_html_e('Support', 'netwarden'); ?></h2>
        <p>
            <?php
            printf(
                /* translators: %1$s: Link to documentation with HTML anchor tag, %2$s: Support email address with mailto link */
                esc_html__('Need help? Visit our %1$s or contact support at %2$s', 'netwarden'),
                sprintf('<a href="%s" target="_blank">%s</a>', esc_url('https://netwarden.com/docs'), esc_html__('documentation', 'netwarden')),
                sprintf('<a href="mailto:%s">%s</a>', esc_attr('support@netwarden.com'), esc_html('support@netwarden.com'))
            );
            ?>
        </p>
    </div>
</div>
