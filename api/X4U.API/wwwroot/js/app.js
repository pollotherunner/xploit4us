/**
 * Exploit4us - Vulnerability Database
 * Main Application JavaScript
 */

// ==========================================================================
// Configuration
// ==========================================================================

const SORT_FIELDS = {
    vuln: [
        { value: 'LastModifiedDate', label: 'Last Modified' },
        { value: 'PublishedDate', label: 'Published' },
        { value: 'BaseScore', label: 'CVSS Score' },
        { value: 'CveId', label: 'CVE ID' }
    ],
    exploit: [
        { value: 'DatePublished', label: 'Date Published' },
        { value: 'GithubStars', label: 'GitHub Stars' },
        { value: 'Title', label: 'Title' }
    ]
};

const DEFAULT_SORT = {
    vuln: [{ field: 'LastModifiedDate', dir: 'desc' }],
    exploit: [{ field: 'DatePublished', dir: 'desc' }]
};

// ==========================================================================
// State Management
// ==========================================================================

const state = {
    vuln: {
        data: null,
        pageNum: 1,
        baseUrl: '/api/vulnerabilities',
        containerId: 'vulnerabilityResults',
        renderFn: null,
        cursorStack: [],
        sortSlots: [{ field: 'LastModifiedDate', dir: 'desc' }]
    },
    exploit: {
        data: null,
        pageNum: 1,
        baseUrl: '/api/exploits',
        containerId: 'exploitResults',
        renderFn: null,
        cursorStack: [],
        sortSlots: [{ field: 'DatePublished', dir: 'desc' }]
    }
};

let vulnSearchTimeout = null;
let exploitSearchTimeout = null;

// ==========================================================================
// Debounce Functions
// ==========================================================================

function debouncedSearchVulnerabilities() {
    clearTimeout(vulnSearchTimeout);
    vulnSearchTimeout = setTimeout(searchVulnerabilities, 500);
}

function debouncedSearchExploits() {
    clearTimeout(exploitSearchTimeout);
    exploitSearchTimeout = setTimeout(searchExploits, 500);
}

// ==========================================================================
// Navigation & History
// ==========================================================================

window.addEventListener('popstate', function (event) {
    const s = event.state;
    if (s) {
        if (s.page === 'home') goHome();
        else if (s.page === 'vulnDetail' && s.cveId) showVulnDetail(s.cveId, false);
        else if (s.page === 'exploitDetail' && s.exploitId) showExploitDetail(s.exploitId, false);
    } else {
        goHome();
    }
});

function showTab(name) {
    document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.getElementById(name).classList.add('active');
    document.querySelectorAll('.tab').forEach((tab, i) => {
        if ((name === 'vulnerabilities' && i === 0) || (name === 'exploits' && i === 1)) {
            tab.classList.add('active');
        }
    });
}

function goHome() {
    document.getElementById('mainContent').classList.remove('hide');
    document.getElementById('vulnDetailPage').classList.remove('active');
    document.getElementById('exploitDetailPage').classList.remove('active');
}

function navigateHome() {
    goHome();
    history.pushState({ page: 'home' }, '', '/');
}

function navigateToTab(tabName) {
    showTab(tabName);
    goHome();
    history.pushState({ page: 'home' }, '', '/');
}

function showVulnDetail(cveId, pushState = true) {
    document.getElementById('mainContent').classList.add('hide');
    document.getElementById('vulnDetailPage').classList.add('active');
    document.getElementById('exploitDetailPage').classList.remove('active');
    if (pushState) {
        history.pushState({ page: 'vulnDetail', cveId }, '', '#vuln/' + encodeURIComponent(cveId));
    }
    loadVulnerabilityDetail(cveId);
}

function showExploitDetail(exploitId, pushState = true) {
    document.getElementById('mainContent').classList.add('hide');
    document.getElementById('vulnDetailPage').classList.remove('active');
    document.getElementById('exploitDetailPage').classList.add('active');
    if (pushState) {
        history.pushState({ page: 'exploitDetail', exploitId }, '', '#exploit/' + exploitId);
    }
    loadExploitDetail(exploitId);
}

// ==========================================================================
// Utility Functions
// ==========================================================================

function buildQueryParams(base, filters) {
    const params = new URLSearchParams();
    Object.entries(filters).forEach(([key, value]) => {
        if (value === '' || value === null || value === undefined) return;
        if (Array.isArray(value)) {
            value.forEach(v => params.append(key, v));
        } else {
            params.append(key, value);
        }
    });
    return `${base}?${params.toString()}`;
}

function formatCveInput(input) {
    let value = input.value.toUpperCase();
    value = value.replace(/-/g, '');
    value = value.replace(/[^A-Z0-9]/g, '');
    if (value.length <= 3) {
        input.value = value;
    } else if (value.length <= 7) {
        input.value = value.substring(0, 3) + '-' + value.substring(3);
    } else {
        input.value = value.substring(0, 3) + '-' + value.substring(3, 7) + '-' + value.substring(7);
    }
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function copyExploitCode() {
    const code = window.currentExploitCode;
    if (!code) return;
    const button = document.querySelector('.code-actions .copy-btn');
    navigator.clipboard.writeText(code).then(() => {
        button.classList.add('copied');
        setTimeout(() => button.classList.remove('copied'), 2000);
    }).catch(() => {
        const ta = document.createElement('textarea');
        ta.value = code;
        ta.style.cssText = 'position:fixed;left:-999999px';
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
        button.classList.add('copied');
        setTimeout(() => button.classList.remove('copied'), 2000);
    });
}

// ==========================================================================
// Multi-Sort Slot Management
// ==========================================================================

function addSortSlot(tabKey) {
    const tab = state[tabKey];
    if (tab.sortSlots.length >= 3) return;
    tab.sortSlots.push({ field: SORT_FIELDS[tabKey][0].value, dir: 'desc' });
    renderSortSlots(tabKey);
}

function removeSortSlot(tabKey, index) {
    const tab = state[tabKey];
    if (tab.sortSlots.length <= 1) return;
    tab.sortSlots.splice(index, 1);
    renderSortSlots(tabKey);
}

function updateSortSlot(tabKey, index, prop, value) {
    state[tabKey].sortSlots[index][prop] = value;
}

function renderSortSlots(tabKey) {
    const tab = state[tabKey];
    const container = document.getElementById(tabKey === 'vuln' ? 'v_sortContainer' : 'e_sortContainer');
    const fields = SORT_FIELDS[tabKey];

    container.innerHTML = tab.sortSlots.map((slot, i) => `
        <div class="sort-slot">
            <span class="sort-order-label">${i === 0 ? 'Primary' : 'Then'}</span>
            <select onchange="updateSortSlot('${tabKey}', ${i}, 'field', this.value)">
                ${fields.map(f => `<option value="${f.value}" ${f.value === slot.field ? 'selected' : ''}>${f.label}</option>`).join('')}
            </select>
            <select onchange="updateSortSlot('${tabKey}', ${i}, 'dir', this.value)" class="sort-dir-select">
                <option value="desc" ${slot.dir === 'desc' ? 'selected' : ''}>Descending</option>
                <option value="asc" ${slot.dir === 'asc' ? 'selected' : ''}>Ascending</option>
            </select>
            ${tab.sortSlots.length > 1 ? `<button class="btn-remove-sort" onclick="removeSortSlot('${tabKey}', ${i})" title="Remove">×</button>` : ''}
        </div>
    `).join('');
}

function getSortParams(tabKey) {
    return state[tabKey].sortSlots.map(s => `${s.field}:${s.dir}`);
}

// ==========================================================================
// URL Persistence
// ==========================================================================

function saveFiltersToUrl(tabKey) {
    const filters = collectFilters(tabKey);
    const params = new URLSearchParams();
    params.set('tab', tabKey === 'vuln' ? 'vulnerabilities' : 'exploits');
    Object.entries(filters).forEach(([key, value]) => {
        if (value === '' || value === null || value === undefined) return;
        if (Array.isArray(value)) {
            value.forEach(v => params.append(key, v));
        } else {
            params.set(key, value);
        }
    });
    const qs = params.toString();
    const url = qs ? `/?${qs}` : '/';
    history.replaceState({ page: 'home' }, '', url);
}

function loadFiltersFromUrl() {
    const params = new URLSearchParams(window.location.search);
    if (!params.has('tab')) return null;

    const tab = params.get('tab') === 'vulnerabilities' ? 'vuln' : 'exploit';

    const setVal = (id, key) => {
        const el = document.getElementById(id);
        if (el && params.has(key)) el.value = params.get(key);
    };

    if (tab === 'vuln') {
        setVal('v_cveId', 'CveId');
        setVal('v_cveYear', 'CveYear');
        setVal('v_sourceName', 'SourceName');
        setVal('v_baseSeverity', 'BaseSeverity');
        setVal('v_cvssVersion', 'CvssVersion');
        setVal('v_minBaseScore', 'MinBaseScore');
        setVal('v_maxBaseScore', 'MaxBaseScore');
        setVal('v_vulnStatus', 'VulnStatus');
        setVal('v_hasExploit', 'HasExploit');
        setVal('v_mainSearch', 'DescriptionContains');
        setVal('v_pageSize', 'PageSize');
    } else {
        setVal('e_sourceName', 'SourceName');
        setVal('e_author', 'Author');
        setVal('e_type', 'Type');
        setVal('e_platform', 'Platform');
        setVal('e_isVerified', 'IsVerified');
        setVal('e_minGithubStars', 'MinGithubStars');
        setVal('e_cveId', 'CveId');
        setVal('e_mainSearch', 'TitleContains');
        setVal('e_pageSize', 'PageSize');
    }

    const sortEntries = params.getAll('SortBy');
    if (sortEntries.length > 0) {
        const slots = sortEntries.map(entry => {
            const parts = entry.split(':');
            return { field: parts[0], dir: parts[1] || 'desc' };
        });
        state[tab].sortSlots = slots;
    }

    return tab;
}

// ==========================================================================
// Collect Filters
// ==========================================================================

function collectFilters(tabKey) {
    if (tabKey === 'vuln') {
        const sortBy = getSortParams('vuln');
        const yearVal = document.getElementById('v_cveYear').value;
        return {
            CveId: document.getElementById('v_cveId').value.toUpperCase() || null,
            CveYear: yearVal ? parseInt(yearVal, 10) : null,
            SourceName: document.getElementById('v_sourceName').value || null,
            DescriptionContains: document.getElementById('v_mainSearch').value || null,
            VulnStatus: document.getElementById('v_vulnStatus').value || null,
            MinBaseScore: document.getElementById('v_minBaseScore').value || null,
            MaxBaseScore: document.getElementById('v_maxBaseScore').value || null,
            BaseSeverity: document.getElementById('v_baseSeverity').value || null,
            CvssVersion: document.getElementById('v_cvssVersion').value || null,
            HasExploit: document.getElementById('v_hasExploit').value || null,
            SortBy: sortBy,
            PageSize: document.getElementById('v_pageSize').value,
            Cursor: null
        };
    } else {
        const sortBy = getSortParams('exploit');
        return {
            SourceName: document.getElementById('e_sourceName').value || null,
            TitleContains: document.getElementById('e_mainSearch').value || null,
            Author: document.getElementById('e_author').value || null,
            Type: document.getElementById('e_type').value || null,
            Platform: document.getElementById('e_platform').value || null,
            IsVerified: document.getElementById('e_isVerified').value || null,
            MinGithubStars: document.getElementById('e_minGithubStars').value || null,
            CveId: document.getElementById('e_cveId').value.toUpperCase() || null,
            SortBy: sortBy,
            PageSize: document.getElementById('e_pageSize').value,
            Cursor: null
        };
    }
}

// ==========================================================================
// Search Functions
// ==========================================================================

async function searchVulnerabilities() {
    const filters = collectFilters('vuln');
    state.vuln.pageNum = 1;
    state.vuln.cursorStack = [];
    const url = buildQueryParams(state.vuln.baseUrl, filters);
    saveFiltersToUrl('vuln');
    await fetchAndDisplay(url, 'vuln', filters);
}

async function searchExploits() {
    const filters = collectFilters('exploit');
    state.exploit.pageNum = 1;
    state.exploit.cursorStack = [];
    const url = buildQueryParams(state.exploit.baseUrl, filters);
    saveFiltersToUrl('exploit');
    await fetchAndDisplay(url, 'exploit', filters);
}

// ==========================================================================
// Fetch & Display
// ==========================================================================

async function fetchAndDisplay(url, tabKey, filters) {
    const tab = state[tabKey];
    const container = document.getElementById(tab.containerId);
    container.innerHTML = '<div class="loading">Loading...</div>';

    try {
        const response = await fetch(url);
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const data = await response.json();

        tab.data = data;

        container.innerHTML =
            tab.renderFn(data) +
            renderPaginationControls(data, tab.pageNum, tabKey);

    } catch (error) {
        container.innerHTML = `<div class="error">Error: ${error.message}</div>`;
    }
}

// ==========================================================================
// Pagination with Cursor Stack
// ==========================================================================

function renderPaginationControls(data, pageNum, tabKey) {
    if (!data || !data.items) return '';
    return `
        <div class="pagination-controls">
            <div class="pagination-info">
                <span>Showing ${data.items.length} of ${data.totalCount} results</span>
                <span style="color: #d20001; font-weight: 600;">Page ${pageNum}</span>
            </div>
            <div class="pagination-buttons">
                <button class="btn btn-sm ${pageNum <= 1 ? 'disabled' : ''}"
                        onclick="goToPreviousPage('${tabKey}')"
                        ${pageNum <= 1 ? 'disabled' : ''}>
                    ← Prev
                </button>
                <button class="btn btn-sm ${!data.hasMore ? 'disabled' : ''}"
                        onclick="goToNextPage('${tabKey}')"
                        ${!data.hasMore ? 'disabled' : ''}>
                    Next →
                </button>
            </div>
        </div>
    `;
}

async function goToNextPage(tabKey) {
    const tab = state[tabKey];
    if (!tab.data || !tab.data.nextCursor) return;

    tab.cursorStack.push(tab.data.nextCursor);

    const filters = collectFilters(tabKey);
    filters.Cursor = tab.data.nextCursor;
    const url = buildQueryParams(tabKey === 'vuln' ? state.vuln.baseUrl : state.exploit.baseUrl, filters);
    tab.pageNum++;
    await fetchAndDisplay(url, tabKey, filters);
}

async function goToPreviousPage(tabKey) {
    const tab = state[tabKey];
    if (tab.cursorStack.length < 2) return;

    tab.cursorStack.pop();
    const prevCursor = tab.cursorStack.pop();
    if (!prevCursor) return;

    const filters = collectFilters(tabKey);
    filters.Cursor = prevCursor;
    tab.cursorStack.push(prevCursor);
    const url = buildQueryParams(tabKey === 'vuln' ? state.vuln.baseUrl : state.exploit.baseUrl, filters);
    tab.pageNum = Math.max(1, tab.pageNum - 1);
    await fetchAndDisplay(url, tabKey, filters);
}

// ==========================================================================
// Render Functions
// ==========================================================================

function renderVulnerabilities(data) {
    if (!data.items || data.items.length === 0) {
        return '<div class="empty-state"><p>No vulnerabilities found</p></div>';
    }
    return `
        <div class="stats">
            <span>Total: ${data.totalCount}</span>
            <span>Showing: ${data.items.length}</span>
            <span>Has More: ${data.hasMore ? 'Yes' : 'No'}</span>
        </div>
        <div class="table-wrapper">
            <table>
                <thead>
                    <tr>
                        <th>CVE ID</th>
                        <th>Severity</th>
                        <th>Score</th>
                        <th class="col-hide-mobile">Status</th>
                        <th class="col-hide-mobile">Description</th>
                        <th class="col-hide-mobile">Published</th>
                        <th>Exploits</th>
                        <th>Action</th>
                    </tr>
                </thead>
                <tbody>
                    ${data.items.map(v => `
                        <tr class="clickable" onclick="showVulnDetail('${v.cveId}')">
                            <td style="font-weight: 600; color: #ff3333;">${v.cveId || 'N/A'}</td>
                            <td class="severity-${(v.baseSeverity || 'low').toLowerCase()}">${v.baseSeverity || 'N/A'}</td>
                            <td>${v.baseScore != null ? v.baseScore.toFixed(1) : 'N/A'}</td>
                            <td class="col-hide-mobile">${v.vulnStatus || 'N/A'}</td>
                            <td class="col-hide-mobile" style="max-width: 400px; overflow: hidden; text-overflow: ellipsis;">${v.description ? v.description.substring(0, 80) + '...' : 'N/A'}</td>
                            <td class="col-hide-mobile">${v.publishedDate ? new Date(v.publishedDate).toLocaleDateString() : 'N/A'}</td>
                            <td>${v.exploitsCount > 0 ? `<span class="exploit-count">${v.exploitsCount}</span>` : '-'}</td>
                            <td><button class="btn btn-sm btn-view" onclick="event.stopPropagation(); showVulnDetail('${v.cveId}')">View</button></td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        </div>
    `;
}

function renderExploits(data) {
    if (!data.items || data.items.length === 0) {
        return '<div class="empty-state"><p>No exploits found</p></div>';
    }
    return `
        <div class="stats">
            <span>Total: ${data.totalCount}</span>
            <span>Showing: ${data.items.length}</span>
            <span>Has More: ${data.hasMore ? 'Yes' : 'No'}</span>
        </div>
        <div class="table-wrapper">
            <table>
                <thead>
                    <tr>
                        <th>Source</th>
                        <th>Title</th>
                        <th class="col-hide-mobile">Type</th>
                        <th class="col-hide-mobile">Platform</th>
                        <th class="col-hide-mobile">Author</th>
                        <th class="col-hide-mobile">Date</th>
                        <th class="col-hide-mobile">Stats</th>
                        <th>Action</th>
                    </tr>
                </thead>
                <tbody>
                    ${data.items.map(e => {
        const isGithub = e.sourceName === 'GitHub';
        const sourceBadge = isGithub
            ? '<span class="badge" style="background: #0f3977; color: #fff;">GitHub</span>'
            : '<span class="badge" style="background: #d20001; color: #fff;">ExploitDB</span>';
        const statsHtml = isGithub
            ? `<span style="font-size: 11px; color: #888;">⭐ ${e.githubStars || 0}</span>`
            : '';
        return `
            <tr class="clickable" onclick="showExploitDetail(${e.id})">
                <td>${sourceBadge}</td>
                <td style="max-width: 300px; overflow: hidden; text-overflow: ellipsis;">${e.title || 'N/A'}</td>
                <td class="col-hide-mobile"><span class="badge">${e.type || 'N/A'}</span></td>
                <td class="col-hide-mobile"><span class="badge">${e.platform || 'N/A'}</span></td>
                <td class="col-hide-mobile">${e.author || 'Anonymous'}</td>
                <td class="col-hide-mobile">${e.datePublished ? new Date(e.datePublished).toLocaleDateString() : 'N/A'}</td>
                <td class="col-hide-mobile">${statsHtml}</td>
                <td><button class="btn btn-sm btn-view" onclick="event.stopPropagation(); showExploitDetail(${e.id})">View</button></td>
            </tr>
        `;
    }).join('')}
                </tbody>
            </table>
        </div>
    `;
}

state.vuln.renderFn = renderVulnerabilities;
state.exploit.renderFn = renderExploits;

// ==========================================================================
// Detail Page Loaders
// ==========================================================================

async function loadVulnerabilityDetail(cveId) {
    document.getElementById('vulnBreadcrumbId').textContent = cveId;
    document.getElementById('vulnDetailId').textContent = cveId;
    document.getElementById('vulnDetailGrid').innerHTML = '<div class="loading">Loading...</div>';
    document.getElementById('vulnDetailDescription').textContent = '';
    document.getElementById('vulnExploitsList').innerHTML = '';

    try {
        const response = await fetch(`/api/vulnerabilities/${encodeURIComponent(cveId)}`);
        if (!response.ok) throw new Error('Failed to load');
        const vuln = await response.json();
        if (!vuln || !vuln.cveId) throw new Error('Vulnerability not found');

        document.getElementById('vulnDetailGrid').innerHTML = `
            <div class="detail-item">
                <div class="detail-label">CVE ID</div>
                <div class="detail-value" style="color: #ff3333; font-weight: 600;">${vuln.cveId}</div>
            </div>
            <div class="detail-item">
                <div class="detail-label">Source</div>
                <div class="detail-value">${vuln.sourceName || 'N/A'}</div>
            </div>
            <div class="detail-item">
                <div class="detail-label">Severity</div>
                <div class="detail-value severity-${(vuln.baseSeverity || 'low').toLowerCase()}">${vuln.baseSeverity || 'N/A'} ${vuln.baseScore != null ? '(' + vuln.baseScore.toFixed(1) + ')' : ''}</div>
            </div>
            <div class="detail-item">
                <div class="detail-label">CVSS Version</div>
                <div class="detail-value">${vuln.cvssVersion || 'N/A'}</div>
            </div>
            <div class="detail-item">
                <div class="detail-label">Vector String</div>
                <div class="detail-value" style="font-family: monospace; font-size: 12px;">${vuln.vectorString || 'N/A'}</div>
            </div>
            <div class="detail-item">
                <div class="detail-label">Status</div>
                <div class="detail-value">${vuln.vulnStatus || 'N/A'}</div>
            </div>
            <div class="detail-item">
                <div class="detail-label">Published</div>
                <div class="detail-value">${vuln.publishedDate ? new Date(vuln.publishedDate).toLocaleString() : 'N/A'}</div>
            </div>
            <div class="detail-item">
                <div class="detail-label">Last Modified</div>
                <div class="detail-value">${vuln.lastModifiedDate ? new Date(vuln.lastModifiedDate).toLocaleString() : 'N/A'}</div>
            </div>
        `;

        document.getElementById('vulnDetailDescription').textContent = vuln.description || 'No description available';
        loadVulnerabilityExploits(cveId);

    } catch (error) {
        document.getElementById('vulnDetailGrid').innerHTML = `<div class="error">Error loading vulnerability: ${error.message}</div>`;
    }
}

async function loadVulnerabilityExploits(cveId) {
    const container = document.getElementById('vulnExploitsList');
    try {
        const response = await fetch(`/api/vulnerabilities/${encodeURIComponent(cveId)}/exploits`);
        if (!response.ok) throw new Error('Failed to load');
        const data = await response.json();
        const exploits = Array.isArray(data) ? data : (data.items || []);

        document.getElementById('vulnExploitsCount').textContent = exploits.length;

        if (!exploits.length) {
            container.innerHTML = '<div class="empty-state">No exploits available for this vulnerability</div>';
            return;
        }

        container.innerHTML = `
            <div class="related-table-wrapper">
                <table class="related-table">
                    <thead>
                        <tr>
                            <th>Source</th><th>Title</th><th>Type</th><th>Platform</th><th>Author</th><th>Action</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${exploits.map(e => {
            const isGithub = e.sourceName === 'GitHub';
            const sourceBadge = isGithub
                ? '<span class="badge" style="background: #0f3977; color: #fff;">GitHub</span>'
                : '<span class="badge" style="background: #d20001; color: #fff;">ExploitDB</span>';
            return `
                <tr>
                    <td>${sourceBadge}</td>
                    <td>
                        <div style="font-weight: 500;">${e.title || 'N/A'}</div>
                        <div style="font-size: 10px; color: #666;">${e.author || 'Anonymous'}</div>
                    </td>
                    <td><span class="badge">${e.type || 'N/A'}</span></td>
                    <td><span class="badge">${e.platform || 'N/A'}</span></td>
                    <td><span class="badge">${e.author || 'N/A'}</span></td>
                    <td><button class="btn btn-sm btn-view" onclick="showExploitDetail('${e.id}')">View</button></td>
                </tr>
            `;
        }).join('')}
                    </tbody>
                </table>
            </div>
        `;
    } catch (error) {
        container.innerHTML = '<div class="empty-state">No exploits found</div>';
        document.getElementById('vulnExploitsCount').textContent = '0';
    }
}

async function loadExploitCode(exploitId) {
    try {
        const response = await fetch(`/api/exploits/${exploitId}/code`);
        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`HTTP ${response.status} - ${errorText}`);
        }
        const data = await response.json();
        return data.code || 'No code available';
    } catch (error) {
        console.error('Error loading exploit code:', error);
        return `Error loading exploit code: ${error.message}`;
    }
}

async function loadExploitDetail(exploitId) {
    document.getElementById('exploitBreadcrumbId').textContent = exploitId;
    document.getElementById('exploitDetailId').textContent = exploitId;
    document.getElementById('exploitDetailGrid').innerHTML = '<div class="loading">Loading...</div>';
    document.getElementById('exploitDetailTitle').textContent = '';
    document.getElementById('exploitDetailCode').textContent = '';
    document.getElementById('exploitVulnsList').innerHTML = '';

    try {
        const response = await fetch(`/api/exploits/${exploitId}`);
        if (!response.ok) throw new Error('Failed to load');
        const exploit = await response.json();
        if (!exploit || !exploit.id) throw new Error('Exploit not found');

        const isGithub = exploit.sourceName === 'GitHub';

        document.getElementById('exploitDetailGrid').innerHTML = `
            <div class="detail-item">
                <div class="detail-label">Exploit ID</div>
                <div class="detail-value" style="color: #ff3333; font-weight: 600;">${exploit.id}</div>
            </div>
            <div class="detail-item">
                <div class="detail-label">Source</div>
                <div class="detail-value">${exploit.sourceName || 'N/A'}</div>
            </div>
            <div class="detail-item">
                <div class="detail-label">Type</div>
                <div class="detail-value">${exploit.type || 'N/A'}</div>
            </div>
            <div class="detail-item">
                <div class="detail-label">Platform</div>
                <div class="detail-value">${exploit.platform || 'N/A'}</div>
            </div>
            <div class="detail-item">
                <div class="detail-label">Author</div>
                <div class="detail-value">${exploit.author || 'Anonymous'}</div>
            </div>
            <div class="detail-item">
                <div class="detail-label">Published</div>
                <div class="detail-value">${exploit.datePublished ? new Date(exploit.datePublished).toLocaleString() : 'N/A'}</div>
            </div>
            ${isGithub ? `
            <div class="detail-item">
                <div class="detail-label">GitHub Stars</div>
                <div class="detail-value">${exploit.githubStars != null ? '⭐ ' + exploit.githubStars : 'N/A'}</div>
            </div>` : ''}
        `;

        document.getElementById('exploitDetailTitle').textContent = exploit.title || 'N/A';

        const codeElement = document.getElementById('exploitDetailCode');
        if (isGithub) {
            codeElement.innerHTML = `<a href="${exploit.pocUrl}" target="_blank" rel="noopener noreferrer" style="color: #d20001; font-family: monospace;">${exploit.pocUrl}</a>`;
        } else {
            codeElement.innerHTML = '<div class="loading">Loading exploit code...</div>';
            loadExploitCode(exploitId).then(code => {
                const escapedCode = escapeHtml(code);
                codeElement.innerHTML = `<pre><code class="language-bash">${escapedCode}</code></pre>`;
                hljs.highlightElement(codeElement.querySelector('code'));
                window.currentExploitCode = code;
            });
        }

        loadExploitVulnerabilities(exploitId);

    } catch (error) {
        document.getElementById('exploitDetailGrid').innerHTML = `<div class="error">Error loading exploit: ${error.message}</div>`;
    }
}

async function loadExploitVulnerabilities(exploitId) {
    const container = document.getElementById('exploitVulnsList');
    try {
        const response = await fetch(`/api/exploits/${exploitId}/vulnerabilities`);
        if (!response.ok) throw new Error('Failed to load');
        const data = await response.json();
        const vulns = Array.isArray(data) ? data : [];

        document.getElementById('exploitVulnsCount').textContent = vulns.length;

        if (!vulns.length) {
            container.innerHTML = '<div class="empty-state">No vulnerabilities linked to this exploit</div>';
            return;
        }

        container.innerHTML = `
            <div class="related-table-wrapper">
                <table class="related-table">
                    <thead>
                        <tr>
                            <th>CVE ID</th><th>Severity</th><th>Score</th><th>Status</th><th>Description</th><th>Action</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${vulns.map(v => `
                            <tr>
                                <td style="font-weight: 600; color: #ff3333;">${v.cveId || 'N/A'}</td>
                                <td class="severity-${(v.baseSeverity || 'low').toLowerCase()}">${v.baseSeverity || 'N/A'}</td>
                                <td>${v.baseScore != null ? v.baseScore.toFixed(1) : 'N/A'}</td>
                                <td>${v.vulnStatus || 'N/A'}</td>
                                <td style="max-width: 300px; overflow: hidden; text-overflow: ellipsis;">${v.description ? v.description.substring(0, 60) + '...' : 'N/A'}</td>
                                <td><button class="btn btn-sm btn-view" onclick="showVulnDetail('${v.cveId}')">View</button></td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            </div>
        `;
    } catch (error) {
        container.innerHTML = '<div class="empty-state">No vulnerabilities found</div>';
        document.getElementById('exploitVulnsCount').textContent = '0';
    }
}

// ==========================================================================
// Clear Filters
// ==========================================================================

function clearVulnerabilityFilters() {
    ['v_cveId', 'v_cveYear', 'v_sourceName', 'v_baseSeverity', 'v_cvssVersion',
        'v_minBaseScore', 'v_maxBaseScore', 'v_vulnStatus', 'v_hasExploit', 'v_mainSearch'].forEach(id => {
            const el = document.getElementById(id);
            if (el) {
                if (el.tagName === 'SELECT') el.selectedIndex = 0;
                else el.value = '';
            }
        });
    state.vuln.sortSlots = [{ field: 'LastModifiedDate', dir: 'desc' }];
    state.vuln.cursorStack = [];
    state.vuln.pageNum = 1;
    state.vuln.data = null;
    renderSortSlots('vuln');
    history.replaceState({ page: 'home' }, '', '/');
}

function clearExploitFilters() {
    ['e_author', 'e_type', 'e_platform', 'e_isVerified', 'e_minGithubStars', 'e_cveId', 'e_mainSearch'].forEach(id => {
        const el = document.getElementById(id);
        if (el) {
            if (el.tagName === 'SELECT') el.selectedIndex = 0;
            else el.value = '';
        }
    });
    document.getElementById('e_sourceName').selectedIndex = 0;
    state.exploit.sortSlots = [{ field: 'DatePublished', dir: 'desc' }];
    state.exploit.cursorStack = [];
    state.exploit.pageNum = 1;
    state.exploit.data = null;
    renderSortSlots('exploit');
    history.replaceState({ page: 'home' }, '', '/');
}

// ==========================================================================
// Initial Load
// ==========================================================================

function handleInitialLoad() {
    const hash = window.location.hash;
    if (hash.startsWith('#vuln/')) {
        showVulnDetail(decodeURIComponent(hash.substring(6)), false);
        return;
    } else if (hash.startsWith('#exploit/')) {
        const id = parseInt(hash.substring(9));
        if (!isNaN(id)) showExploitDetail(id, false);
        return;
    }

    const restoredTab = loadFiltersFromUrl();
    if (restoredTab) {
        renderSortSlots(restoredTab);
        if (restoredTab === 'vuln') {
            showTab('vulnerabilities');
            searchVulnerabilities();
        } else {
            showTab('exploits');
            searchExploits();
        }
    }
}

// ==========================================================================
// Initialize Application
// ==========================================================================

renderSortSlots('vuln');
renderSortSlots('exploit');
handleInitialLoad();

if (!window.location.search && !window.location.hash) {
    searchVulnerabilities();
    searchExploits();
}
