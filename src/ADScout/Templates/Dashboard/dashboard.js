/**
 * AD-Scout Dashboard JavaScript
 * Provides interactivity for the live dashboard
 */

(function() {
    'use strict';

    // Dashboard state
    const Dashboard = {
        autoRefresh: false,
        refreshInterval: 60,
        refreshTimer: null,
        lastUpdate: null
    };

    // Initialize on DOM ready
    document.addEventListener('DOMContentLoaded', function() {
        initDropdowns();
        initExpandableRows();
        initSearch();
        initFilters();
        initCopyButtons();
        initAutoRefresh();
        initExportButtons();
        initBaselineButtons();
        initScanButton();
        updateTimestamps();
    });

    /**
     * Initialize dropdown menus
     */
    function initDropdowns() {
        document.querySelectorAll('.dropdown').forEach(function(dropdown) {
            const toggle = dropdown.querySelector('.dropdown-toggle');
            const menu = dropdown.querySelector('.dropdown-menu');

            if (toggle && menu) {
                toggle.addEventListener('click', function(e) {
                    e.stopPropagation();
                    menu.classList.toggle('show');
                });
            }
        });

        // Close dropdowns when clicking outside
        document.addEventListener('click', function() {
            document.querySelectorAll('.dropdown-menu.show').forEach(function(menu) {
                menu.classList.remove('show');
            });
        });
    }

    /**
     * Initialize expandable table rows
     */
    function initExpandableRows() {
        document.querySelectorAll('.expandable-row').forEach(function(row) {
            row.addEventListener('click', function() {
                const ruleId = this.dataset.ruleId;
                const detailsRow = document.querySelector('.row-details[data-rule-id="' + ruleId + '"]');

                if (detailsRow) {
                    detailsRow.classList.toggle('expanded');
                    this.classList.toggle('expanded');

                    // Load remediation if not already loaded
                    if (detailsRow.classList.contains('expanded')) {
                        loadRemediation(ruleId, detailsRow);
                    }
                }
            });
        });
    }

    /**
     * Load remediation script via API
     */
    function loadRemediation(ruleId, container) {
        const remediationContainer = container.querySelector('.remediation-container');
        if (!remediationContainer || remediationContainer.dataset.loaded === 'true') {
            return;
        }

        remediationContainer.innerHTML = '<div class="loading"><span class="spinner"></span> Loading remediation...</div>';

        fetch('/api/remediation/' + encodeURIComponent(ruleId))
            .then(function(response) { return response.json(); })
            .then(function(data) {
                if (data.success && data.remediation) {
                    remediationContainer.innerHTML =
                        '<div class="remediation-code"><pre>' + escapeHtml(data.remediation) + '</pre></div>' +
                        '<button class="copy-btn" data-copy="' + escapeAttr(data.remediation) + '">Copy</button>';
                    remediationContainer.dataset.loaded = 'true';
                    initCopyButtons();
                } else {
                    remediationContainer.innerHTML = '<p class="text-muted">No remediation available for this rule.</p>';
                }
            })
            .catch(function(error) {
                remediationContainer.innerHTML = '<p class="text-muted">Failed to load remediation: ' + escapeHtml(error.message) + '</p>';
            });
    }

    /**
     * Initialize search functionality
     */
    function initSearch() {
        const searchInput = document.getElementById('search-input');
        if (!searchInput) return;

        let debounceTimer;
        searchInput.addEventListener('input', function() {
            clearTimeout(debounceTimer);
            debounceTimer = setTimeout(function() {
                filterFindings();
            }, 300);
        });
    }

    /**
     * Initialize filter dropdowns
     */
    function initFilters() {
        document.querySelectorAll('.filter-select').forEach(function(select) {
            select.addEventListener('change', function() {
                filterFindings();
            });
        });
    }

    /**
     * Filter findings table based on search and filters
     */
    function filterFindings() {
        const searchInput = document.getElementById('search-input');
        const categoryFilter = document.getElementById('category-filter');
        const severityFilter = document.getElementById('severity-filter');

        const searchTerm = searchInput ? searchInput.value.toLowerCase() : '';
        const category = categoryFilter ? categoryFilter.value : '';
        const severity = severityFilter ? severityFilter.value : '';

        document.querySelectorAll('.findings-table tbody tr.finding-row').forEach(function(row) {
            const ruleId = (row.dataset.ruleId || '').toLowerCase();
            const ruleName = (row.dataset.ruleName || '').toLowerCase();
            const rowCategory = row.dataset.category || '';
            const rowSeverity = row.dataset.severity || '';
            const description = (row.dataset.description || '').toLowerCase();

            let visible = true;

            // Search filter
            if (searchTerm && !(ruleId.includes(searchTerm) || ruleName.includes(searchTerm) || description.includes(searchTerm))) {
                visible = false;
            }

            // Category filter
            if (category && rowCategory !== category) {
                visible = false;
            }

            // Severity filter
            if (severity && rowSeverity !== severity) {
                visible = false;
            }

            row.style.display = visible ? '' : 'none';

            // Also hide/show associated details row
            const detailsRow = document.querySelector('.row-details[data-rule-id="' + row.dataset.ruleId + '"]');
            if (detailsRow) {
                detailsRow.style.display = visible ? '' : 'none';
            }
        });

        updateFilteredCount();
    }

    /**
     * Update filtered count display
     */
    function updateFilteredCount() {
        const visibleRows = document.querySelectorAll('.findings-table tbody tr.finding-row:not([style*="display: none"])');
        const totalRows = document.querySelectorAll('.findings-table tbody tr.finding-row');
        const countDisplay = document.getElementById('filtered-count');

        if (countDisplay) {
            if (visibleRows.length === totalRows.length) {
                countDisplay.textContent = totalRows.length + ' findings';
            } else {
                countDisplay.textContent = visibleRows.length + ' of ' + totalRows.length + ' findings';
            }
        }
    }

    /**
     * Initialize copy to clipboard buttons
     */
    function initCopyButtons() {
        document.querySelectorAll('.copy-btn').forEach(function(btn) {
            if (btn.dataset.initialized) return;
            btn.dataset.initialized = 'true';

            btn.addEventListener('click', function(e) {
                e.stopPropagation();
                const textToCopy = this.dataset.copy || this.previousElementSibling.textContent;

                navigator.clipboard.writeText(textToCopy).then(function() {
                    btn.textContent = 'Copied!';
                    btn.classList.add('copied');
                    setTimeout(function() {
                        btn.textContent = 'Copy';
                        btn.classList.remove('copied');
                    }, 2000);
                }).catch(function(err) {
                    console.error('Failed to copy:', err);
                });
            });
        });
    }

    /**
     * Initialize auto-refresh functionality
     */
    function initAutoRefresh() {
        const autoRefreshToggle = document.getElementById('auto-refresh-toggle');
        const refreshIntervalInput = document.getElementById('refresh-interval');

        if (autoRefreshToggle) {
            autoRefreshToggle.addEventListener('change', function() {
                Dashboard.autoRefresh = this.checked;
                if (Dashboard.autoRefresh) {
                    startAutoRefresh();
                } else {
                    stopAutoRefresh();
                }
            });
        }

        if (refreshIntervalInput) {
            refreshIntervalInput.addEventListener('change', function() {
                Dashboard.refreshInterval = parseInt(this.value, 10) || 60;
                if (Dashboard.autoRefresh) {
                    stopAutoRefresh();
                    startAutoRefresh();
                }
            });
        }

        // Check if auto-refresh is enabled via data attribute
        const dashboardEl = document.querySelector('[data-auto-refresh]');
        if (dashboardEl && dashboardEl.dataset.autoRefresh === 'true') {
            Dashboard.autoRefresh = true;
            Dashboard.refreshInterval = parseInt(dashboardEl.dataset.refreshInterval, 10) || 60;
            startAutoRefresh();
        }
    }

    /**
     * Start auto-refresh timer
     */
    function startAutoRefresh() {
        if (Dashboard.refreshTimer) {
            clearInterval(Dashboard.refreshTimer);
        }

        Dashboard.refreshTimer = setInterval(function() {
            refreshDashboard();
        }, Dashboard.refreshInterval * 1000);

        updateAutoRefreshIndicator(true);
    }

    /**
     * Stop auto-refresh timer
     */
    function stopAutoRefresh() {
        if (Dashboard.refreshTimer) {
            clearInterval(Dashboard.refreshTimer);
            Dashboard.refreshTimer = null;
        }

        updateAutoRefreshIndicator(false);
    }

    /**
     * Update auto-refresh indicator
     */
    function updateAutoRefreshIndicator(active) {
        const indicator = document.querySelector('.auto-refresh');
        if (indicator) {
            indicator.style.display = active ? '' : 'none';
        }
    }

    /**
     * Refresh dashboard data
     */
    function refreshDashboard() {
        fetch('/api/status')
            .then(function(response) { return response.json(); })
            .then(function(data) {
                updateScoreDisplay(data);
                Dashboard.lastUpdate = new Date();
                updateTimestamps();
            })
            .catch(function(error) {
                console.error('Failed to refresh:', error);
            });
    }

    /**
     * Update score display elements
     */
    function updateScoreDisplay(data) {
        const scoreValue = document.querySelector('.score-value');
        if (scoreValue) {
            scoreValue.textContent = data.score;
            scoreValue.className = 'score-value ' + getScoreClass(data.score);
        }

        const gradeValue = document.querySelector('.score-grade');
        if (gradeValue) {
            gradeValue.textContent = data.grade;
            gradeValue.className = 'score-grade ' + data.grade;
        }

        const findingsCount = document.querySelector('.stat-value[data-stat="findings"]');
        if (findingsCount) {
            findingsCount.textContent = data.totalFindings;
        }

        const rulesCount = document.querySelector('.stat-value[data-stat="rules"]');
        if (rulesCount) {
            rulesCount.textContent = data.rulesWithFindings;
        }
    }

    /**
     * Get CSS class for score
     */
    function getScoreClass(score) {
        if (score >= 90) return 'good';
        if (score >= 70) return 'medium';
        if (score >= 50) return 'high';
        return 'critical';
    }

    /**
     * Initialize export buttons
     */
    function initExportButtons() {
        document.querySelectorAll('[data-export]').forEach(function(btn) {
            btn.addEventListener('click', function(e) {
                e.preventDefault();
                const format = this.dataset.export;
                window.location.href = '/api/export/' + format;
            });
        });
    }

    /**
     * Initialize baseline buttons
     */
    function initBaselineButtons() {
        const saveBaselineBtn = document.getElementById('save-baseline');
        if (saveBaselineBtn) {
            saveBaselineBtn.addEventListener('click', function() {
                saveBaseline();
            });
        }
    }

    /**
     * Save current scan as baseline
     */
    function saveBaseline() {
        const btn = document.getElementById('save-baseline');
        if (!btn) return;

        btn.disabled = true;
        btn.textContent = 'Saving...';

        fetch('/api/baseline', { method: 'POST' })
            .then(function(response) { return response.json(); })
            .then(function(data) {
                if (data.success) {
                    btn.textContent = 'Baseline Saved!';
                    setTimeout(function() {
                        btn.textContent = 'Save as Baseline';
                        btn.disabled = false;
                    }, 2000);

                    // Refresh to show comparison
                    setTimeout(function() {
                        window.location.reload();
                    }, 1500);
                } else {
                    btn.textContent = 'Error: ' + (data.error || 'Unknown error');
                    btn.disabled = false;
                }
            })
            .catch(function(error) {
                btn.textContent = 'Error';
                btn.disabled = false;
                console.error('Failed to save baseline:', error);
            });
    }

    /**
     * Initialize scan button
     */
    function initScanButton() {
        const scanBtn = document.getElementById('run-scan');
        if (scanBtn) {
            scanBtn.addEventListener('click', function() {
                runNewScan();
            });
        }
    }

    /**
     * Run a new scan
     */
    function runNewScan() {
        const btn = document.getElementById('run-scan');
        if (!btn) return;

        btn.disabled = true;
        btn.innerHTML = '<span class="spinner"></span> Scanning...';

        fetch('/api/scan', { method: 'POST' })
            .then(function(response) { return response.json(); })
            .then(function(data) {
                if (data.success) {
                    btn.textContent = 'Scan Complete!';
                    setTimeout(function() {
                        window.location.reload();
                    }, 1000);
                } else {
                    btn.textContent = 'Error: ' + (data.error || 'Scan failed');
                    btn.disabled = false;
                }
            })
            .catch(function(error) {
                btn.textContent = 'Error';
                btn.disabled = false;
                console.error('Failed to run scan:', error);
            });
    }

    /**
     * Update timestamps to relative format
     */
    function updateTimestamps() {
        document.querySelectorAll('[data-timestamp]').forEach(function(el) {
            const timestamp = el.dataset.timestamp;
            if (timestamp) {
                el.textContent = formatRelativeTime(new Date(timestamp));
            }
        });

        // Update last refresh indicator
        if (Dashboard.lastUpdate) {
            const lastRefreshEl = document.querySelector('.last-refresh');
            if (lastRefreshEl) {
                lastRefreshEl.textContent = 'Last updated: ' + formatRelativeTime(Dashboard.lastUpdate);
            }
        }
    }

    /**
     * Format date as relative time
     */
    function formatRelativeTime(date) {
        const now = new Date();
        const diffMs = now - date;
        const diffSecs = Math.floor(diffMs / 1000);
        const diffMins = Math.floor(diffSecs / 60);
        const diffHours = Math.floor(diffMins / 60);
        const diffDays = Math.floor(diffHours / 24);

        if (diffSecs < 60) return 'just now';
        if (diffMins < 60) return diffMins + ' minute' + (diffMins === 1 ? '' : 's') + ' ago';
        if (diffHours < 24) return diffHours + ' hour' + (diffHours === 1 ? '' : 's') + ' ago';
        if (diffDays < 7) return diffDays + ' day' + (diffDays === 1 ? '' : 's') + ' ago';

        return date.toLocaleDateString();
    }

    /**
     * Escape HTML entities
     */
    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    /**
     * Escape attribute value
     */
    function escapeAttr(text) {
        return text.replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    }

    /**
     * Simple bar chart rendering
     */
    function renderBarChart(container, data, options) {
        options = options || {};
        const maxValue = Math.max.apply(null, data.map(function(d) { return d.value; }));

        let html = '<div class="bar-chart">';
        data.forEach(function(item) {
            const width = maxValue > 0 ? (item.value / maxValue) * 100 : 0;
            html += '<div class="bar-item">' +
                '<span class="bar-label">' + escapeHtml(item.label) + '</span>' +
                '<div class="bar-track">' +
                '<div class="bar-fill ' + (item.color || '') + '" style="width: ' + width + '%"></div>' +
                '</div>' +
                '<span class="bar-value">' + item.value + '</span>' +
                '</div>';
        });
        html += '</div>';

        container.innerHTML = html;
    }

    /**
     * Render trend line chart (simple SVG)
     */
    function renderTrendChart(container, data, options) {
        options = options || {};
        const width = container.clientWidth || 400;
        const height = options.height || 150;
        const padding = 30;

        if (!data || data.length < 2) {
            container.innerHTML = '<div class="empty-state">Not enough data for trend chart</div>';
            return;
        }

        const maxValue = Math.max.apply(null, data.map(function(d) { return d.value; }));
        const minValue = Math.min.apply(null, data.map(function(d) { return d.value; }));
        const range = maxValue - minValue || 1;

        const points = data.map(function(d, i) {
            const x = padding + (i / (data.length - 1)) * (width - 2 * padding);
            const y = height - padding - ((d.value - minValue) / range) * (height - 2 * padding);
            return x + ',' + y;
        });

        const pathD = 'M ' + points.join(' L ');

        let svg = '<svg width="' + width + '" height="' + height + '" class="trend-chart-svg">';

        // Grid lines
        for (let i = 0; i <= 4; i++) {
            const y = padding + (i / 4) * (height - 2 * padding);
            svg += '<line x1="' + padding + '" y1="' + y + '" x2="' + (width - padding) + '" y2="' + y + '" stroke="var(--color-border)" stroke-dasharray="2"/>';
        }

        // Path
        svg += '<path d="' + pathD + '" fill="none" stroke="var(--color-accent)" stroke-width="2"/>';

        // Points
        data.forEach(function(d, i) {
            const x = padding + (i / (data.length - 1)) * (width - 2 * padding);
            const y = height - padding - ((d.value - minValue) / range) * (height - 2 * padding);
            svg += '<circle cx="' + x + '" cy="' + y + '" r="4" fill="var(--color-accent)"/>';
        });

        svg += '</svg>';
        container.innerHTML = svg;
    }

    // Expose functions globally for inline event handlers
    window.Dashboard = Dashboard;
    window.filterFindings = filterFindings;
    window.saveBaseline = saveBaseline;
    window.runNewScan = runNewScan;
    window.refreshDashboard = refreshDashboard;

})();
