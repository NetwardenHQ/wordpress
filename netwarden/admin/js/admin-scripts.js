/**
 * Netwarden Admin JavaScript
 */

(function($) {
    'use strict';

    $(document).ready(function() {

        /**
         * Save credentials form submission
         */
        $('#netwarden-credentials-form').on('submit', function(e) {
            e.preventDefault();

            var $form = $(this);
            var $submitBtn = $('#netwarden-save-btn');
            var $message = $('#netwarden-message');

            // Get form data
            var tenantId = $('#netwarden_tenant_id').val().trim();
            var apiKey = $('#netwarden_api_key').val().trim();

            // Basic validation
            if (!tenantId || !apiKey) {
                showMessage('Please fill in all fields', 'error');
                return;
            }

            // Validate tenant ID format (10 alphanumeric characters)
            if (!/^[a-zA-Z0-9]{10}$/.test(tenantId)) {
                showMessage('Tenant ID must be exactly 10 alphanumeric characters', 'error');
                return;
            }

            // Validate API key format (starts with nw_sk_)
            if (!apiKey.startsWith('nw_sk_')) {
                showMessage('API Key must start with "nw_sk_"', 'error');
                return;
            }

            // Disable submit button
            $submitBtn.prop('disabled', true).html('Saving... <span class="netwarden-spinner"></span>');

            // Send AJAX request
            $.ajax({
                url: netwardenAdmin.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'netwarden_save_credentials',
                    nonce: netwardenAdmin.nonce,
                    tenant_id: tenantId,
                    api_key: apiKey
                },
                success: function(response) {
                    if (response.success) {
                        showMessage(response.data.message, 'success');
                        // Reload page after 1.5 seconds
                        setTimeout(function() {
                            window.location.reload();
                        }, 1500);
                    } else {
                        showMessage(response.data.message, 'error');
                        $submitBtn.prop('disabled', false).text('Save Credentials');
                    }
                },
                error: function() {
                    showMessage('An error occurred while saving credentials', 'error');
                    $submitBtn.prop('disabled', false).text('Save Credentials');
                }
            });
        });

        /**
         * Send metrics now button
         */
        $('#netwarden-test-btn').on('click', function(e) {
            e.preventDefault();

            var $btn = $(this);
            var $message = $('#netwarden-message');

            // Disable button
            $btn.prop('disabled', true).html('Sending... <span class="netwarden-spinner"></span>');

            // Send AJAX request
            $.ajax({
                url: netwardenAdmin.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'netwarden_test_connection',
                    nonce: netwardenAdmin.nonce
                },
                success: function(response) {
                    if (response.success) {
                        showMessage(response.data.message, 'success');
                        // Reload page after 1.5 seconds to show updated timestamp
                        setTimeout(function() {
                            window.location.reload();
                        }, 1500);
                    } else {
                        showMessage(response.data.message, 'error');
                        $btn.prop('disabled', false).text('Send Metrics Now');
                    }
                },
                error: function() {
                    showMessage('An error occurred while sending metrics', 'error');
                    $btn.prop('disabled', false).text('Send Metrics Now');
                }
            });
        });

        /**
         * Delete credentials button
         */
        $('#netwarden-delete-btn').on('click', function(e) {
            e.preventDefault();

            if (!confirm('Are you sure you want to delete your Netwarden credentials? This will stop metric collection.')) {
                return;
            }

            var $btn = $(this);
            var $message = $('#netwarden-message');

            // Disable button
            $btn.prop('disabled', true).html('Deleting... <span class="netwarden-spinner"></span>');

            // Send AJAX request
            $.ajax({
                url: netwardenAdmin.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'netwarden_delete_credentials',
                    nonce: netwardenAdmin.nonce
                },
                success: function(response) {
                    if (response.success) {
                        showMessage(response.data.message, 'success');
                        // Reload page after 1.5 seconds
                        setTimeout(function() {
                            window.location.reload();
                        }, 1500);
                    } else {
                        showMessage(response.data.message, 'error');
                        $btn.prop('disabled', false).text('Delete Credentials');
                    }
                },
                error: function() {
                    showMessage('An error occurred while deleting credentials', 'error');
                    $btn.prop('disabled', false).text('Delete Credentials');
                }
            });
        });

        /**
         * Show message helper function
         */
        function showMessage(message, type) {
            var $message = $('#netwarden-message');

            $message
                .removeClass('success error info')
                .addClass(type)
                .text(message)
                .fadeIn();

            // Auto-hide success messages after 5 seconds
            if (type === 'success') {
                setTimeout(function() {
                    $message.fadeOut();
                }, 5000);
            }
        }

        /**
         * Real-time validation for tenant ID
         */
        $('#netwarden_tenant_id').on('input', function() {
            var value = $(this).val();
            var isValid = /^[a-zA-Z0-9]{10}$/.test(value);

            if (value.length > 0 && !isValid) {
                $(this).css('border-color', '#dc3232');
            } else {
                $(this).css('border-color', '');
            }
        });

        /**
         * Real-time validation for API key
         */
        $('#netwarden_api_key').on('input', function() {
            var value = $(this).val();
            var isValid = value.startsWith('nw_sk_');

            if (value.length > 0 && !isValid) {
                $(this).css('border-color', '#dc3232');
            } else {
                $(this).css('border-color', '');
            }
        });

    });

})(jQuery);
