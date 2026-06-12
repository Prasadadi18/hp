// ngrok's free tier serves an HTML browser-warning interstitial to fetch()
// calls, which breaks every JSON API response over the tunnel. Sending this
// header on all requests bypasses the warning and returns the real API data.
(function patchFetchForNgrok() {
    const _origFetch = window.fetch.bind(window);
    window.fetch = (input, init = {}) => {
        const headers = new Headers((init && init.headers) || {});
        if (!headers.has('ngrok-skip-browser-warning')) {
            headers.set('ngrok-skip-browser-warning', 'true');
        }
        return _origFetch(input, { ...init, headers });
    };
})();

document.addEventListener('DOMContentLoaded', () => {
    // ── 1. DOM ELEMENTS ──
    // Login Screen Elements
    const loginWrapper = document.getElementById('loginWrapper');
    const authForm = document.getElementById('authForm');
    const submitBtn = document.getElementById('submitBtn');
    const alertBox = document.getElementById('alertBox');
    const alertText = document.getElementById('alertText');
    const alertIcon = document.getElementById('alertIcon');
    const formTitle = document.getElementById('formTitle');
    const formSubtitle = document.getElementById('formSubtitle');
    const deptGroup = document.getElementById('deptGroup');
    const passGroup = document.getElementById('passGroup');
    const usernameInput = document.getElementById('username');
    const passwordInput = document.getElementById('password');
    const departmentInput = document.getElementById('department');
    const toggleText = document.getElementById('toggleText');
    const toggleMode = document.getElementById('toggleMode');

    // Credential Helper Elements
    const userSelector = document.getElementById('userSelector');
    const helperInfo = document.getElementById('helperInfo');
    const helperRole = document.getElementById('helperRole');
    const helperRegion = document.getElementById('helperRegion');
    const helperPassword = document.getElementById('helperPassword');
    const copyPasswordBtn = document.getElementById('copyPasswordBtn');
    const helperNoteRow = document.getElementById('helperNoteRow');

    // Banners & Disclaimers
    const previewBanner = document.getElementById('previewBanner');
    const closePreviewBanner = document.getElementById('closePreviewBanner');

    // Dashboard View Elements
    const dashboardWrapper = document.getElementById('dashboardWrapper');
    const userNameDisplay = document.getElementById('headerUsername');
    const userRoleDisplay = document.getElementById('headerRole');
    const userHomeRegionDisplay = document.getElementById('userHomeRegionDisplay');
    const userLastLoginDisplay = document.getElementById('userLastLoginDisplay');
    const dashActivePassword = document.getElementById('dashActivePassword');
    const dashCopyPassBtn = document.getElementById('dashCopyPassBtn');
    const logoutBtn = document.getElementById('logoutBtn');
    const headerUserAvatar = document.getElementById('headerUserAvatar');

    // Workspaces
    const workspaceDeveloper = document.getElementById('workspaceDeveloper');
    const workspaceFinance = document.getElementById('workspaceFinance');
    const workspaceHR = document.getElementById('workspaceHR');
    const workspaceSales = document.getElementById('workspaceSales');
    const workspaceAdmin = document.getElementById('workspaceAdmin');
    const filesTabList = document.getElementById('filesTabList');

    // Simulation Form Elements
    const simForm = document.getElementById('simForm');
    const simHour = document.getElementById('simHour');
    const simRegion = document.getElementById('simRegion');
    const simDownload = document.getElementById('simDownload');
    const simFailed = document.getElementById('simFailed');
    const simTravel = document.getElementById('simTravel');
    const autoTravelVal = document.getElementById('autoTravelVal');
    const simVpn = document.getElementById('simVpn');
    
    // Sliders value indicators
    const hourVal = document.getElementById('hourVal');
    const regionVal = document.getElementById('regionVal');
    const downloadVal = document.getElementById('downloadVal');
    const failedVal = document.getElementById('failedVal');
    const simLaunchBtn = document.getElementById('simLaunchBtn');

    // Live indicators badges
    const badgeTime = document.getElementById('badgeTime');
    const badgeGeo = document.getElementById('badgeGeo');
    const badgeDownload = document.getElementById('badgeDownload');
    const badgeFailed = document.getElementById('badgeFailed');
    const badgeTravel = document.getElementById('badgeTravel');
    const badgeVpn = document.getElementById('badgeVpn');

    // Download warning modal Elements
    const downloadWarningModal = document.getElementById('downloadWarningModal');
    const downloadWarningText = document.getElementById('downloadWarningText');
    const cancelDownloadBtn = document.getElementById('cancelDownloadBtn');
    const proceedDownloadBtn = document.getElementById('proceedDownloadBtn');

    // Impossible travel warning modal Elements
    const travelWarningModal = document.getElementById('travelWarningModal');
    const travelWarningText = document.getElementById('travelWarningText');
    const revertRegionBtn = document.getElementById('revertRegionBtn');
    const acceptTravelBtn = document.getElementById('acceptTravelBtn');

    // Stats Footer Elements
    const footerDailyLimit = document.getElementById('footerDailyLimit');
    const footerSessionDownloads = document.getElementById('footerSessionDownloads');
    const footerDevices = document.getElementById('footerDevices');
    const footerLastLocation = document.getElementById('footerLastLocation');

    // Results Overlay Elements
    const resultOverlay = document.getElementById('resultOverlay');
    const resultStatusPill = document.getElementById('resultStatusPill');
    const resultStatusText = document.getElementById('resultStatusText');
    const xgbScoreVal = document.getElementById('xgbScoreVal');
    const lgbScoreVal = document.getElementById('lgbScoreVal');
    const ensembleScoreVal = document.getElementById('ensembleScoreVal');
    const resultReasonsList = document.getElementById('resultReasonsList');
    const rotationNotice = document.getElementById('rotationNotice');
    const rotationNewPassword = document.getElementById('rotationNewPassword');
    const copyNewPasswordBtn = document.getElementById('copyNewPasswordBtn');
    const closeOverlayBtn = document.getElementById('closeOverlayBtn');

    // ── 2. STATE MANAGEMENT ──
    let isLoginMode = true;
    let loggedInUser = null;
    let loggedInPassword = null;
    let userProfile = null;
    let loginHistory = null;
    let prevLoginInfo = null;        // pre-reset memory returned by the login response
    let actualFailedAttempts = 0;    // real DB wrong-password count (read-only display)
    let availableUsers = [];
    let demoUsers = [];
    let sessionDownloads = 0.0;
    let isRotatedState = false; // Triggers logout on result dialog close
    let pendingDownloadSize = 0; // Holds download size during security modal prompt
    let sessionWatchTimer = null; // polls for server-side credential rotation

    const SESSION_KEY = 'hpe_portal_session';

    function saveSession() {
        if (!loggedInUser) return;
        try {
            sessionStorage.setItem(SESSION_KEY, JSON.stringify({
                user: loggedInUser, pw: loggedInPassword, prev: prevLoginInfo
            }));
        } catch {}
    }
    function clearSession() {
        try { sessionStorage.removeItem(SESSION_KEY); } catch {}
    }

    const TRAVEL_WINDOW_MS = 6 * 3600 * 1000; // matches backend impossible-travel window

    // ── DEPARTMENT PORTAL CONFIG ──
    // Each role gets its own accent theme, hero branding, KPIs, quick apps
    // and announcements so the portal feels different per department.
    const DEPT_PORTAL = {
        'Developer': {
            cls: 'dept-developer',
            dept: 'Engineering Division',
            tagline: 'Build. Ship. Secure. Your pipelines are green today.',
            workspaceTitle: 'Engineering Workspace',
            kpis: [['12/12', 'Builds Passing'], ['7', 'Open Pull Requests'], ['3', 'Deploys Today']],
            links: [['⌨️', 'Git Repositories'], ['🔁', 'CI/CD Pipelines'], ['🐞', 'Issue Tracker'], ['📚', 'API Documentation']],
            news: [
                ['RELEASE', 'threat-engine v2.4 promoted to production', 'Platform Team • 2h ago'],
                ['MAINTENANCE', 'Staging cluster upgrade window Friday 22:00 UTC', 'Infra • 1d ago'],
                ['POLICY', 'New code-signing requirement for all release branches', 'Security • 3d ago']
            ]
        },
        'Finance': {
            cls: 'dept-finance',
            dept: 'Finance & Treasury',
            tagline: 'Q2 close is in progress — 14 invoices await review.',
            workspaceTitle: 'Finance Workspace',
            kpis: [['14', 'Pending Invoices'], ['68%', 'Q2 Budget Used'], ['3', 'Reports Due']],
            links: [['📊', 'ERP Console'], ['🧾', 'Expense Portal'], ['🏦', 'Treasury Vault'], ['📑', 'Audit Reports']],
            news: [
                ['DEADLINE', 'Q2 revenue ledger submissions close Friday', 'Controller • 4h ago'],
                ['UPDATE', 'New travel reimbursement rates effective this month', 'Treasury • 2d ago'],
                ['AUDIT', 'External audit fieldwork begins June 23', 'Compliance • 4d ago']
            ]
        },
        'HR': {
            cls: 'dept-hr',
            dept: 'People & Culture',
            tagline: '6 new hires onboarding this week — welcome them aboard!',
            workspaceTitle: 'HR Workspace',
            kpis: [['248', 'Headcount'], ['6', 'Onboarding'], ['11', 'Open Positions']],
            links: [['🗂️', 'HRIS Console'], ['💰', 'Payroll'], ['🎯', 'Recruiting'], ['🏥', 'Benefits Portal']],
            news: [
                ['EVENT', 'All-hands town hall scheduled for June 18', 'People Ops • 6h ago'],
                ['REMINDER', 'Mid-year performance check-ins open Monday', 'HRBP • 1d ago'],
                ['BENEFITS', 'Updated parental leave policy now live', 'Benefits • 5d ago']
            ]
        },
        'Sales': {
            cls: 'dept-sales',
            dept: 'Global Sales',
            tagline: 'Pipeline at $6.2M — 4 deals in closing stage.',
            workspaceTitle: 'Sales Workspace',
            kpis: [['$6.2M', 'Active Pipeline'], ['4', 'Deals Closing'], ['82%', 'Quota Attained']],
            links: [['🤝', 'CRM Console'], ['💬', 'Quotes & Pricing'], ['📄', 'Contracts'], ['🌍', 'Lead Explorer']],
            news: [
                ['WIN', 'Acme Corporation renewal signed — $4.5M ARR', 'Sales Ops • 1h ago'],
                ['ENABLEMENT', 'New competitive battlecards posted', 'Enablement • 2d ago'],
                ['TARGET', 'Q3 territory plans due end of month', 'RevOps • 3d ago']
            ]
        },
        'Admin': {
            cls: 'dept-admin',
            dept: 'Security Operations',
            tagline: 'All systems nominal. Zero-trust posture enforced.',
            workspaceTitle: 'Security & System Control',
            kpis: [['6/6', 'Services Online'], ['0', 'Open Incidents'], ['24h', 'Since Last Rotation']],
            links: [['🔐', 'Vault Console'], ['📈', 'Kibana Logs'], ['🛡️', 'Admin Console'], ['🖥️', 'Infra Status']],
            news: [
                ['SECURITY', 'Credential rotation playbooks updated to v3', 'SecOps • 3h ago'],
                ['DRILL', 'Quarterly incident-response drill next Tuesday', 'CISO Office • 1d ago'],
                ['NOTICE', 'AppRole token TTL reduced to 60 minutes', 'Vault Admin • 2d ago']
            ]
        }
    };
    const DEFAULT_PORTAL = {
        cls: '', dept: 'Enterprise Division',
        tagline: 'Your secure department workspace.',
        workspaceTitle: 'Department Workspace',
        kpis: [['—', 'Sessions'], ['—', 'Tasks'], ['—', 'Messages']],
        links: [['📧', 'Mail'], ['📅', 'Calendar'], ['📁', 'Drive'], ['❓', 'Helpdesk']],
        news: [['INFO', 'Welcome to the HPE enterprise portal', 'IT • today']]
    };

    function applyPortalTheme(role, userId) {
        const cfg = DEPT_PORTAL[role] || DEFAULT_PORTAL;

        // Department accent class on the wrapper drives all theming via CSS vars
        dashboardWrapper.classList.remove('dept-developer', 'dept-finance', 'dept-hr', 'dept-sales', 'dept-admin');
        if (cfg.cls) dashboardWrapper.classList.add(cfg.cls);

        // Hero strip
        const hour = new Date().getHours();
        const daypart = hour < 12 ? 'Good morning' : (hour < 17 ? 'Good afternoon' : 'Good evening');
        document.getElementById('heroDept').textContent = cfg.dept;
        document.getElementById('heroGreeting').textContent = `${daypart}, ${userId}`;
        document.getElementById('heroTagline').textContent = cfg.tagline;
        document.getElementById('heroDate').textContent = new Date().toLocaleDateString(undefined,
            { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' });
        document.getElementById('workspacePanelTitle').textContent = cfg.workspaceTitle;

        // KPI cards
        const kpiRow = document.getElementById('kpiRow');
        kpiRow.innerHTML = '';
        cfg.kpis.forEach(([val, lbl]) => {
            const card = document.createElement('div');
            card.className = 'kpi-card';
            const v = document.createElement('div');
            v.className = 'kpi-val';
            v.textContent = val;
            const l = document.createElement('div');
            l.className = 'kpi-lbl';
            l.textContent = lbl;
            card.appendChild(v);
            card.appendChild(l);
            kpiRow.appendChild(card);
        });

        // Quick apps
        const quickLinks = document.getElementById('quickLinks');
        quickLinks.innerHTML = '';
        cfg.links.forEach(([icon, label]) => {
            const a = document.createElement('div');
            a.className = 'quick-link';
            const i = document.createElement('span');
            i.className = 'quick-link-icon';
            i.textContent = icon;
            const t = document.createElement('span');
            t.textContent = label;
            a.appendChild(i);
            a.appendChild(t);
            quickLinks.appendChild(a);
        });

        // Announcements
        const announceList = document.getElementById('announceList');
        announceList.innerHTML = '';
        cfg.news.forEach(([tag, title, meta]) => {
            const item = document.createElement('div');
            item.className = 'announce-item';
            const titleRow = document.createElement('div');
            titleRow.className = 'announce-title';
            const tagEl = document.createElement('span');
            tagEl.className = 'announce-tag';
            tagEl.textContent = tag;
            titleRow.appendChild(tagEl);
            titleRow.appendChild(document.createTextNode(title));
            const metaEl = document.createElement('div');
            metaEl.className = 'announce-meta';
            metaEl.textContent = meta;
            item.appendChild(titleRow);
            item.appendChild(metaEl);
            announceList.appendChild(item);
        });
    }

    // Alert icons
    const iconSuccess = `<path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline>`;
    const iconError = `<circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line>`;

    const baseUrl = window.location.origin;

    // Alerts helpers
    function showAlert(message, type) {
        alertText.textContent = message;
        alertIcon.innerHTML = type === 'success' ? iconSuccess : iconError;
        alertBox.className = `status-alert alert-${type} show`;
    }

    function hideAlert() {
        alertBox.className = 'status-alert';
    }

    // Toggle Login/Access Mode
    toggleMode.addEventListener('click', (e) => {
        e.preventDefault();
        isLoginMode = !isLoginMode;
        hideAlert();
        
        authForm.style.opacity = '0';
        
        setTimeout(() => {
            if (isLoginMode) {
                formTitle.textContent = 'Secure Gateway';
                formSubtitle.textContent = 'Authenticate to access the enterprise network';
                deptGroup.style.display = 'none';
                passGroup.style.display = 'block';
                passwordInput.required = true;
                submitBtn.textContent = 'Authorize';
                toggleText.innerHTML = 'New employee? <a class="toggle-link" id="toggleMode">Request access</a>';
            } else {
                formTitle.textContent = 'Access Request';
                formSubtitle.textContent = 'Request clearance for the enterprise portal';
                deptGroup.style.display = 'block';
                passGroup.style.display = 'none';
                passwordInput.required = false;
                submitBtn.textContent = 'Submit Request';
                toggleText.innerHTML = 'Already authorized? <a class="toggle-link" id="toggleMode">Sign in</a>';
            }
            
            authForm.style.opacity = '1';
            
            document.getElementById('toggleMode').addEventListener('click', (ev) => {
                ev.preventDefault();
                toggleMode.click();
            });
        }, 300);
    });

    // ── 3. CREDENTIAL HELPER LOAD & MASKING ──
    // fetch() has no timeout — over a flaky tunnel (ngrok) a hung request
    // would leave the helper stuck on "Loading users..." forever.
    function fetchWithTimeout(url, ms = 10000) {
        return fetch(url, { signal: AbortSignal.timeout(ms) });
    }

    async function loadHelperUsers(attempt = 1) {
        try {
            // Fetch demo list and user catalog in parallel; the demo list is
            // optional (failure = everything stays masked, never revealed)
            const [demoResp, usersResp] = await Promise.all([
                fetchWithTimeout(`${baseUrl}/api/auth/demo-users`).catch(() => null),
                fetchWithTimeout(`${baseUrl}/api/auth/users`)
            ]);

            if (demoResp && demoResp.ok) {
                const demoData = await demoResp.json();
                demoUsers = demoData.demo_users || [];
            }

            if (!usersResp.ok) throw new Error("Failed to fetch users");
            availableUsers = await usersResp.json();

            // Populate select dropdown
            userSelector.innerHTML = '<option value="">Select a user account...</option>';
            availableUsers.forEach(u => {
                const isDemo = demoUsers.includes(u.user_id);
                const opt = document.createElement('option');
                opt.value = u.user_id;
                opt.textContent = `${isDemo ? '★ ' : ''}${u.user_id} (${u.role})`;
                userSelector.appendChild(opt);
            });

            // Highlight rotated user password if redirected after rotation
            const rotatedUser = sessionStorage.getItem('rotated_user');
            if (rotatedUser) {
                userSelector.value = rotatedUser;
                userSelector.dispatchEvent(new Event('change'));

                // Add password highlight animation
                helperPassword.parentElement.classList.add('password-highlight-active');
                setTimeout(() => {
                    helperPassword.parentElement.classList.remove('password-highlight-active');
                }, 10000);

                sessionStorage.removeItem('rotated_user');
            }
        } catch (e) {
            console.error("Helper loader error:", e);
            if (attempt < 4) {
                // Auto-retry with backoff — tunnel hiccups are usually transient
                userSelector.innerHTML = `<option value="">Connection slow — retrying (${attempt}/3)...</option>`;
                setTimeout(() => loadHelperUsers(attempt + 1), 2000 * attempt);
            } else {
                userSelector.innerHTML = '<option value="">Failed to load — click to retry</option>';
                userSelector.addEventListener('click', () => loadHelperUsers(), { once: true });
            }
        }
    }

    userSelector.addEventListener('change', async () => {
        helperPassword.parentElement.classList.remove('password-highlight-active');
        
        const selectedUserId = userSelector.value;
        if (!selectedUserId) {
            helperInfo.style.display = 'none';
            return;
        }
        
        // Show the panel immediately so the selection always gives feedback,
        // even if the profile fetch is slow over the tunnel.
        helperInfo.style.display = 'flex';
        const selUser = availableUsers.find(u => u.user_id === selectedUserId);
        helperRole.textContent = selUser ? selUser.role : '…';
        helperRegion.textContent = '…';

        const isDemo = demoUsers.includes(selectedUserId);
        const isRotatedUser = (selectedUserId === sessionStorage.getItem('last_rotated_user'));

        try {
            // Profile (for home region) — timed so a hung request can't freeze the panel
            try {
                const profileResp = await fetchWithTimeout(`${baseUrl}/api/auth/user-profile/${selectedUserId}`, 8000);
                if (profileResp.ok) {
                    const profile = await profileResp.json();
                    helperRole.textContent = profile.role || helperRole.textContent;
                    helperRegion.textContent = profile.home_region || 'Unknown';
                } else {
                    helperRegion.textContent = 'Unknown';
                }
            } catch {
                helperRegion.textContent = 'Unknown';
            }

            if (isDemo || isRotatedUser) {
                let pw = 'password123';
                try {
                    const credResp = await fetchWithTimeout(`${baseUrl}/api/auth/user-credential/${selectedUserId}`, 8000);
                    if (credResp.ok) pw = (await credResp.json()).current_password;
                } catch { /* keep fallback */ }
                helperPassword.textContent = pw;
                copyPasswordBtn.disabled = false;
                copyPasswordBtn.textContent = '📋 Autofill';
                helperNoteRow.style.display = 'none';

                // The post-rotation reveal is ONE-TIME — it exists only to let
                // the locked-out user log back in. Masked again afterwards.
                if (isRotatedUser && !isDemo) {
                    sessionStorage.removeItem('last_rotated_user');
                }
            } else {
                helperPassword.textContent = '••••••••';
                copyPasswordBtn.disabled = true;
                copyPasswordBtn.textContent = '🔒 Masked';
                helperNoteRow.style.display = 'block';
            }
        } catch (err) {
            console.error("Helper select error:", err);
            // Panel stays visible with whatever we have — never blank out
        }
    });

    // Copy/autofill helper button
    copyPasswordBtn.addEventListener('click', () => {
        const passVal = helperPassword.textContent;
        if (passVal === '••••••••') return;
        
        passwordInput.value = passVal;
        usernameInput.value = userSelector.value;
        
        const originalText = copyPasswordBtn.textContent;
        copyPasswordBtn.textContent = '📋 Filled!';
        setTimeout(() => {
            copyPasswordBtn.textContent = originalText;
        }, 1200);
    });

    // ── 4. ACCESS / REGISTER SUBMISSION ──
    authForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        hideAlert();
        
        const username = usernameInput.value.trim();
        const password = passwordInput.value;
        const department = departmentInput.value.trim();

        if (!username || (isLoginMode && !password) || (!isLoginMode && !department)) {
            showAlert('Please complete all required fields.', 'error');
            return;
        }

        submitBtn.disabled = true;
        submitBtn.textContent = isLoginMode ? 'Verifying...' : 'Processing...';

        try {
            const endpoint = isLoginMode ? '/api/auth/login' : '/api/auth/register';
            const body = isLoginMode ? { username, password } : { username, department };

            const response = await fetch(`${baseUrl}${endpoint}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(body)
            });

            const data = await response.json();

            if (response.ok && data.success) {
                showAlert(data.message, 'success');
                submitBtn.textContent = isLoginMode ? 'Access Granted' : 'Request Submitted';
                submitBtn.style.background = 'linear-gradient(135deg, #10b981 0%, #059669 100%)';
                
                if (isLoginMode) {
                    loggedInUser = data.user_id || username;
                    loggedInPassword = password;
                    // Back in successfully — the post-rotation reveal is no longer needed
                    sessionStorage.removeItem('rotated_user');
                    sessionStorage.removeItem('last_rotated_user');
                    // Pre-reset login memory: accumulated failed attempts and
                    // previous session info returned by the login endpoint
                    prevLoginInfo = {
                        failed_attempts: data.failed_attempts || 0,
                        last_login: data.last_login || null,
                        last_login_region: data.last_login_region || null
                    };
                    saveSession();
                    await initializeDashboard(loggedInUser);
                } else {
                    // Registration Success — Immediate Workspace Preview Jump
                    if (data.password) {
                        loggedInUser = data.user_id;
                        loggedInPassword = data.password;
                        prevLoginInfo = null; // brand-new account, no history
                        saveSession();

                        previewBanner.style.display = 'flex';

                        setTimeout(async () => {
                            await initializeDashboard(loggedInUser);
                            
                            // Restore auth form view for logout reload
                            isLoginMode = true;
                            formTitle.textContent = 'Secure Gateway';
                            formSubtitle.textContent = 'Authenticate to access the enterprise network';
                            deptGroup.style.display = 'none';
                            passGroup.style.display = 'block';
                            passwordInput.required = true;
                            submitBtn.textContent = 'Authorize';
                            toggleText.innerHTML = 'New employee? <a class="toggle-link" id="toggleMode">Request access</a>';
                            authForm.reset();
                        }, 1500);
                    } else {
                        setTimeout(() => {
                            isLoginMode = false;
                            toggleMode.click();
                            authForm.reset();
                        }, 2000);
                    }
                }
            } else {
                showAlert(data.detail || data.message || 'Authentication failed', 'error');
                submitBtn.disabled = false;
                submitBtn.textContent = isLoginMode ? 'Authorize' : 'Submit Request';
                submitBtn.style.background = '';
            }
        } catch (error) {
            console.error(error);
            showAlert('Secure connection aborted. Target unreachable.', 'error');
            submitBtn.disabled = false;
            submitBtn.textContent = isLoginMode ? 'Authorize' : 'Submit Request';
            submitBtn.style.background = '';
        }
    });

    // ── 5. DASHBOARD TRANSITION & INITIALIZATION ──
    async function initializeDashboard(userId) {
        try {
            // Load details
            const [profileResp, credResp] = await Promise.all([
                fetch(`${baseUrl}/api/auth/user-profile/${userId}`),
                fetch(`${baseUrl}/api/auth/user-credential/${userId}`)
            ]);

            if (!profileResp.ok || !credResp.ok) throw new Error("State loader failed");

            userProfile = await profileResp.json();
            const credentials = await credResp.json();

            // Setup Profile sidebar / header
            if (headerUserAvatar) {
                headerUserAvatar.textContent = userId.slice(0, 3) === 'USR' ? userId.slice(4, 6) : userId.slice(0, 1).toUpperCase();
            }
            if (userNameDisplay) userNameDisplay.textContent = userId;
            if (userRoleDisplay) userRoleDisplay.textContent = userProfile.role;
            if (userHomeRegionDisplay) userHomeRegionDisplay.textContent = userProfile.home_region;
            
            // Mask active cleartext password in dashboard and store in custom attr
            if (dashActivePassword) {
                dashActivePassword.textContent = '••••••••';
                dashActivePassword.setAttribute('data-password', credentials.current_password);
            }

            // Load workspaces
            workspaceDeveloper.style.display = 'none';
            workspaceFinance.style.display = 'none';
            workspaceHR.style.display = 'none';
            workspaceSales.style.display = 'none';
            workspaceAdmin.style.display = 'none';

            if (userProfile.role === 'Developer') workspaceDeveloper.style.display = 'block';
            else if (userProfile.role === 'Finance') workspaceFinance.style.display = 'block';
            else if (userProfile.role === 'HR') workspaceHR.style.display = 'block';
            else if (userProfile.role === 'Sales') workspaceSales.style.display = 'block';
            else if (userProfile.role === 'Admin') workspaceAdmin.style.display = 'block';

            // Apply the department-specific portal theme (accent, hero, KPIs,
            // quick apps, announcements)
            applyPortalTheme(userProfile.role, userId);

            // Load Login History (post-login memory: current session time +
            // the region preserved from previous activity)
            const historyResp = await fetch(`${baseUrl}/api/auth/login-history/${userId}`);
            if (historyResp.ok) {
                loginHistory = await historyResp.json();
                footerLastLocation.textContent = loginHistory.last_login_region || userProfile.home_region || 'US-East';
            } else {
                loginHistory = null;
                footerLastLocation.textContent = userProfile.home_region || 'US-East';
            }

            // Failed attempts: the ACTUAL accumulated wrong-password count
            // (pre-reset value from the login response) — read-only display
            actualFailedAttempts = (prevLoginInfo && typeof prevLoginInfo.failed_attempts === 'number')
                ? prevLoginInfo.failed_attempts
                : ((loginHistory && loginHistory.failed_attempts) || 0);
            failedVal.textContent = actualFailedAttempts;

            // Display the PREVIOUS session time and region from the login response
            if (prevLoginInfo && prevLoginInfo.last_login) {
                const d = new Date(prevLoginInfo.last_login);
                userLastLoginDisplay.textContent = `${d.toLocaleString()} (${prevLoginInfo.last_login_region || 'Unknown Region'})`;
            } else {
                userLastLoginDisplay.textContent = 'Never';
            }

            // Setup footer bar values
            const avgDl = userProfile.avg_daily_downloads_mb || 10;
            footerDailyLimit.textContent = `${(avgDl * 3).toFixed(1)} MB`;
            footerSessionDownloads.textContent = `${sessionDownloads.toFixed(1)} MB`;
            footerDevices.textContent = userProfile.num_known_devices || 2;

            // Setup Sliders — region defaults to the PREVIOUS login region so
            // the panel matches recorded memory (no silent travel flag on load)
            simHour.value = userProfile.base_login_hour ? Math.round(userProfile.base_login_hour) : 9;
            simRegion.value = (loginHistory && loginHistory.last_login_region) || userProfile.home_region || 'US-East';
            simDownload.value = userProfile.avg_daily_downloads_mb ? Math.round(userProfile.avg_daily_downloads_mb) : 10;
            simTravel.checked = false;
            simVpn.checked = false;

            // Reset tab displays to dashboard by default
            document.querySelectorAll('.sidebar-item').forEach(i => i.classList.remove('active'));
            document.querySelector('[data-tab="dashboard"]').classList.add('active');
            document.querySelectorAll('.tab-content-panel').forEach(p => p.style.display = 'none');
            document.getElementById('tabContentDashboard').style.display = 'block';

            // Trigger visual text update
            updateSlidersUI();
            runLiveAnomalyCheck();

            // Transition HTML wrappers
            loginWrapper.style.opacity = '0';
            setTimeout(() => {
                loginWrapper.style.display = 'none';
                dashboardWrapper.style.display = 'grid';
                dashboardWrapper.style.opacity = '1';
                hideAlert();
            }, 400);

            // Watch for credential rotation triggered outside this tab
            startSessionWatch();

        } catch (e) {
            console.error("Dashboard initialize error:", e);
            // A failed restore (e.g. stale session after rotation) must not
            // strand the user on a half-loaded dashboard — fall back to login.
            clearSession();
            showAlert("Error preparing simulation session profile data.", "error");
            submitBtn.disabled = false;
            submitBtn.textContent = 'Authorize';
            submitBtn.style.background = '';
        }
    }

    // ── 6. TAB SWAP NAVIGATION ──
    const sidebarItems = document.querySelectorAll('.sidebar-item');
    const tabContentPanels = document.querySelectorAll('.tab-content-panel');
    sidebarItems.forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            const targetTab = item.getAttribute('data-tab');
            
            sidebarItems.forEach(i => i.classList.remove('active'));
            item.classList.add('active');
            
            tabContentPanels.forEach(panel => {
                panel.style.display = 'none';
            });
            
            if (targetTab === 'dashboard') {
                document.getElementById('tabContentDashboard').style.display = 'block';
            } else if (targetTab === 'files') {
                document.getElementById('tabContentFiles').style.display = 'block';
                populateFilesTab();
            } else if (targetTab === 'settings') {
                document.getElementById('tabContentSettings').style.display = 'block';
            } else if (targetTab === 'security') {
                document.getElementById('tabContentSecurity').style.display = 'block';
                document.getElementById('securityAnomalyCount').textContent = document.querySelectorAll('.indicator-badge.anomalous').length;
            }
        });
    });

    function populateFilesTab() {
        filesTabList.innerHTML = '';
        if (!userProfile) return;
        
        const role = userProfile.role;
        let files = [];
        if (role === 'Developer') {
            files = [
                { name: 'hpe-cyber-gateway-proxy (Repository)', sub: 'Engineering Core Proxy codebase • Access: Developer' },
                { name: 'hpe-threat-engine-ml (Repository)', sub: 'ML Ensemble Threat Inference pipeline code • Access: Developer' },
                { name: 'hpe-auth-vault-service (Repository)', sub: 'AppRole & KV credential helper code • Access: Developer' }
            ];
        } else if (role === 'Finance') {
            files = [
                { name: 'hpe_q2_revenue_ledger.pdf', sub: 'Size: 42 MB • Sensitivity: HIGH', size: 42 },
                { name: 'hpe_global_tax_records.xlsx', sub: 'Size: 185 MB • Sensitivity: CRITICAL', size: 185 },
                { name: 'hpe_investor_report_2026.pptx', sub: 'Size: 14 MB • Sensitivity: MEDIUM', size: 14 }
            ];
        } else if (role === 'HR') {
            files = [
                { name: 'hpe_talent_clearence_level3.csv', sub: 'Size: 5 MB • Sensitivity: MEDIUM', size: 5 },
                { name: 'hpe_onboarding_roster_q2.pdf', sub: 'Size: 8 MB • Sensitivity: LOW', size: 8 }
            ];
        } else if (role === 'Sales') {
            files = [
                { name: 'acme_global_leads_details.xlsx', sub: 'Size: 12 MB • Sensitivity: HIGH', size: 12 },
                { name: 'techcorp_solutions_contract.pdf', sub: 'Size: 15 MB • Sensitivity: MEDIUM', size: 15 }
            ];
        } else {
            files = [
                { name: 'HashiCorp Vault Configurations', sub: 'Status: Online • Key Rotation: Dynamic AppRole active' },
                { name: 'PostgreSQL Database Settings', sub: 'Status: Online • Pool allocation: 10 connections active' }
            ];
        }
        
        files.forEach(file => {
            const item = document.createElement('div');
            item.className = 'list-item';
            
            const info = document.createElement('div');
            info.className = 'item-info';
            
            const name = document.createElement('span');
            name.className = 'item-name';
            name.textContent = file.name;
            
            const sub = document.createElement('span');
            sub.className = 'item-sub';
            sub.textContent = file.sub;
            
            info.appendChild(name);
            info.appendChild(sub);
            item.appendChild(info);
            
            if (file.size && (role === 'Finance' || role === 'HR' || role === 'Sales')) {
                const dlBtn = document.createElement('button');
                dlBtn.className = 'mini-btn file-download-trigger';
                dlBtn.textContent = 'Download';
                dlBtn.setAttribute('data-size', file.size);
                dlBtn.addEventListener('click', () => {
                    triggerFileDownload(file.size);
                });
                item.appendChild(dlBtn);
            } else {
                const badge = document.createElement('span');
                badge.className = 'status-pill status-active';
                badge.textContent = 'Authorized';
                item.appendChild(badge);
            }
            
            filesTabList.appendChild(item);
        });
    }

    // ── 7. SLIDERS & INTERACTIVE BEHAVIOR ──
    function updateSlidersUI() {
        const hr = parseInt(simHour.value);
        const padHr = hr.toString().padStart(2, '0');
        hourVal.textContent = `${padHr}:00`;
        
        regionVal.textContent = simRegion.value;
        downloadVal.textContent = `${simDownload.value} MB`;
        failedVal.textContent = actualFailedAttempts;
    }

    // ── IMPOSSIBLE TRAVEL POPUP ──
    // The current region is chosen by the user (not detected via IP). If it
    // differs from the previous login region within the travel window, warn.
    function maybeWarnImpossibleTravel() {
        if (!loginHistory || !loginHistory.last_login || !loginHistory.last_login_region) return;
        const selRegion = simRegion.value;
        if (selRegion === loginHistory.last_login_region) return;

        const elapsedMs = Date.now() - new Date(loginHistory.last_login).getTime();
        if (elapsedMs >= TRAVEL_WINDOW_MS) return;

        const mins = Math.max(1, Math.round(elapsedMs / 60000));
        travelWarningText.innerHTML = `Your previous login was from <strong>${loginHistory.last_login_region}</strong> ${mins} minute(s) ago, but you selected <strong>${selRegion}</strong>.`;
        travelWarningModal.style.display = 'flex';
    }

    revertRegionBtn.addEventListener('click', () => {
        travelWarningModal.style.display = 'none';
        if (loginHistory && loginHistory.last_login_region) {
            simRegion.value = loginHistory.last_login_region;
        }
        updateSlidersUI();
        runLiveAnomalyCheck();
    });

    acceptTravelBtn.addEventListener('click', () => {
        travelWarningModal.style.display = 'none';
    });

    // Slider inputs
    simHour.addEventListener('input', () => { updateSlidersUI(); runLiveAnomalyCheck(); });
    simRegion.addEventListener('change', () => { updateSlidersUI(); runLiveAnomalyCheck(); maybeWarnImpossibleTravel(); });
    simDownload.addEventListener('input', () => { updateSlidersUI(); runLiveAnomalyCheck(); });
    simVpn.addEventListener('change', runLiveAnomalyCheck);

    // Event delegation for workspace file download buttons
    document.addEventListener('click', (e) => {
        if (e.target && e.target.classList.contains('file-download-trigger')) {
            const size = parseInt(e.target.getAttribute('data-size'));
            if (!isNaN(size)) {
                triggerFileDownload(size);
            }
        }
    });

    // ── 8. DOWNLOAD WARNING MODAL & STATS INTERNALS ──
    function triggerFileDownload(size) {
        if (!userProfile) return;
        
        const isDev = userProfile.role === 'Developer';
        const avgDl = userProfile.avg_daily_downloads_mb || 50;
        const isAbnormal = !isDev && (size > avgDl * 3);
        
        if (isAbnormal) {
            pendingDownloadSize = size;
            downloadWarningText.innerHTML = `You are initiating an abnormal file download of <strong>${size} MB</strong>. Your profile typical daily average is <strong>${avgDl} MB</strong>.`;
            downloadWarningModal.style.display = 'flex';
        } else {
            executeDownloadAndSimulate(size);
        }
    }

    function executeDownloadAndSimulate(size) {
        simDownload.value = size;
        downloadVal.textContent = `${size} MB`;
        
        sessionDownloads += size;
        footerSessionDownloads.textContent = `${sessionDownloads.toFixed(1)} MB`;
        
        runLiveAnomalyCheck();
        
        // Highlight simulation panel briefly
        simDownload.style.transform = 'scale(1.05)';
        setTimeout(() => { simDownload.style.transform = 'scale(1)'; }, 300);

        // Submit form
        simForm.dispatchEvent(new Event('submit'));
    }

    cancelDownloadBtn.addEventListener('click', () => {
        downloadWarningModal.style.display = 'none';
        pendingDownloadSize = 0;
    });

    proceedDownloadBtn.addEventListener('click', () => {
        downloadWarningModal.style.display = 'none';
        if (pendingDownloadSize > 0) {
            executeDownloadAndSimulate(pendingDownloadSize);
            pendingDownloadSize = 0;
        }
    });

    // ── 9. LIVE ANOMALY COMPOSER (INCLUDES LIVE TRAVEL VELOCITY DETECTION) ──
    function runLiveAnomalyCheck() {
        if (!userProfile) return;

        const selHour = parseInt(simHour.value);
        const selRegion = simRegion.value;
        const selDownload = parseFloat(simDownload.value);
        const selFailed = actualFailedAttempts;
        const isVpn = simVpn.checked;

        // Check hour deviation
        const baseHour = userProfile.base_login_hour || 9;
        const isShift = userProfile.is_shift_worker || false;
        let diff = Math.abs(selHour - baseHour);
        if (diff > 12) diff = 24 - diff;
        
        const anomalousHour = !isShift && (selHour < 6 || selHour > 22 || diff > 4);
        if (anomalousHour) {
            badgeTime.className = 'indicator-badge anomalous';
            badgeTime.textContent = `🔴 Off-Hours Access (${selHour}:00)`;
        } else {
            badgeTime.className = 'indicator-badge';
            badgeTime.textContent = '🟢 Access Time Normal';
        }

        // Check geo region mismatch
        const homeRegion = userProfile.home_region || 'US-East';
        if (selRegion !== homeRegion) {
            badgeGeo.className = 'indicator-badge anomalous';
            badgeGeo.textContent = `🔴 Region Mismatch: ${selRegion}`;
        } else {
            badgeGeo.className = 'indicator-badge';
            badgeGeo.textContent = '🟢 Region Mismatch: None';
        }

        // Check download volume
        const avgDownload = userProfile.avg_daily_downloads_mb || 50;
        if (selDownload > 500 || selDownload > avgDownload * 8) {
            badgeDownload.className = 'indicator-badge anomalous';
            badgeDownload.textContent = `🔴 Extreme Data Leak: ${selDownload} MB`;
        } else if (selDownload > avgDownload * 2) {
            badgeDownload.className = 'indicator-badge elevated';
            badgeDownload.textContent = `🟡 Elevated Data Volume: ${selDownload} MB`;
        } else {
            badgeDownload.className = 'indicator-badge';
            badgeDownload.textContent = '🟢 Downloads Normal';
        }

        // Check failed attempts
        if (selFailed > 3) {
            badgeFailed.className = 'indicator-badge anomalous';
            badgeFailed.textContent = `🔴 Suspicious Failed Attempts: ${selFailed}`;
        } else if (selFailed > 0) {
            badgeFailed.className = 'indicator-badge elevated';
            badgeFailed.textContent = `🟡 Failed Logins: ${selFailed}`;
        } else {
            badgeFailed.className = 'indicator-badge';
            badgeFailed.textContent = '🟢 Login Attempts Safe';
        }

        // Auto Travel Velocity Anomaly Check — region changed vs previous
        // login AND last login was recent enough that travel is impossible
        let isTravelAnomalous = false;
        if (loginHistory && loginHistory.last_login && loginHistory.last_login_region &&
            loginHistory.last_login_region !== selRegion) {
            const elapsedMs = Date.now() - new Date(loginHistory.last_login).getTime();
            isTravelAnomalous = elapsedMs < TRAVEL_WINDOW_MS;
        }

        // Keep the hidden auto-tracked state + label in sync
        simTravel.checked = isTravelAnomalous;
        if (autoTravelVal) {
            autoTravelVal.textContent = isTravelAnomalous ? '🔴 Flagged' : 'Auto-Tracked';
            autoTravelVal.style.color = isTravelAnomalous ? 'var(--danger)' : 'var(--text-muted)';
        }

        if (isTravelAnomalous) {
            badgeTravel.className = 'indicator-badge anomalous';
            badgeTravel.textContent = `🔴 Impossible Travel: Jump from ${loginHistory.last_login_region}`;
        } else {
            badgeTravel.className = 'indicator-badge';
            badgeTravel.textContent = '🟢 Travel Velocity Normal';
        }

        // VPN detected
        if (isVpn) {
            badgeVpn.className = 'indicator-badge anomalous';
            badgeVpn.textContent = '🔴 VPN Proxy IP Active';
        } else {
            badgeVpn.className = 'indicator-badge';
            badgeVpn.textContent = '🟢 VPN Tunnel Inactive';
        }
    }

    // ── 10. SUBMIT SIMULATION ──
    simForm.addEventListener('submit', async (e) => {
        e.preventDefault();

        simLaunchBtn.disabled = true;
        simLaunchBtn.textContent = 'Running Model Inference...';

        const body = {
            username: loggedInUser,
            password: loggedInPassword,
            login_hour: parseInt(simHour.value),
            ip_region: simRegion.value,
            data_downloaded_mb: parseFloat(simDownload.value),
            failed_attempts: actualFailedAttempts,
            impossible_travel: null, // Let backend automatically compute impossible travel!
            is_vpn: simVpn.checked
        };

        try {
            let response = await fetch(`${baseUrl}/api/auth/simulate`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(body)
            });

            // Self-heal stale credentials: the password may have been rotated
            // server-side mid-session (e.g. an admin approving an alert on the
            // console rotates it again). Refresh from Vault and retry once.
            if (response.status === 401 && loggedInUser) {
                const credResp = await fetch(`${baseUrl}/api/auth/user-credential/${loggedInUser}`);
                if (credResp.ok) {
                    const creds = await credResp.json();
                    loggedInPassword = creds.current_password;
                    if (dashActivePassword) {
                        dashActivePassword.setAttribute('data-password', loggedInPassword);
                    }
                    body.password = loggedInPassword;
                    response = await fetch(`${baseUrl}/api/auth/simulate`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(body)
                    });
                }
            }

            if (!response.ok) {
                const errData = await response.json();
                throw new Error(errData.detail || "Inference failed");
            }

            const data = await response.json();

            // Populate overlay metrics
            xgbScoreVal.textContent = (data.xgb_score || 0).toFixed(5);
            lgbScoreVal.textContent = (data.lgb_score || 0).toFixed(5);
            ensembleScoreVal.textContent = (data.ensemble_score || 0).toFixed(5);

            // Setup Action status
            const action = data.threat_action;
            resultStatusPill.className = `result-status status-${action.toLowerCase().replace('_', '')}`;
            resultStatusPill.textContent = action.replace('_', ' ');

            if (action === 'ALLOW') {
                resultStatusText.textContent = "Activity aligned with behavioral baseline.";
                resultStatusPill.style.boxShadow = '';
            } else if (action === 'MONITOR') {
                resultStatusText.textContent = "Behavior deviates mildly. Audit logged.";
                resultStatusPill.style.boxShadow = '';
            } else if (action === 'BLOCK') {
                resultStatusText.textContent = "Anomalous behavior identified. Active session blocked.";
                resultStatusPill.style.boxShadow = '';
            } else { // CRITICAL_ALERT
                resultStatusText.textContent = "Critical threat vector confirmed. Infrastructure and user locked.";
            }

            // Populate reasons
            resultReasonsList.innerHTML = '';
            const reasons = data.event_summary.threat_reasons || [];
            if (reasons.length === 0) {
                const li = document.createElement('li');
                li.textContent = "🟢 Consistent with daily profile logs.";
                resultReasonsList.appendChild(li);
                resultReasonsBox.className = 'reasons-box';
            } else {
                reasons.forEach(r => {
                    const li = document.createElement('li');
                    li.textContent = `⚠️ ${r}`;
                    resultReasonsList.appendChild(li);
                });
                resultReasonsBox.className = 'reasons-box threat';
            }

            // Check if rotation occurred
            if (data.credentials_rotated) {
                rotationNotice.style.display = 'block';
                rotationNewPassword.textContent = data.new_password;
                isRotatedState = true;
                
                // Update local password cache so we can authenticate next attempts or logouts
                loggedInPassword = data.new_password;
                saveSession();

                // Write user credentials metadata to sessionStorage for credential helper auto-highlight on logout
                sessionStorage.setItem('rotated_user', loggedInUser);
                sessionStorage.setItem('last_rotated_user', loggedInUser);
            } else {
                rotationNotice.style.display = 'none';
                isRotatedState = false;
            }

            // Update footer last location
            footerLastLocation.textContent = data.event_summary.ip_region || simRegion.value;

            // Refresh login memory — the simulation became the latest access,
            // so subsequent region changes compare against this region/time
            try {
                const histResp = await fetch(`${baseUrl}/api/auth/login-history/${loggedInUser}`);
                if (histResp.ok) {
                    loginHistory = await histResp.json();
                    runLiveAnomalyCheck();
                }
            } catch (histErr) {
                console.warn("Login history refresh failed:", histErr);
            }

            // Show Overlay
            resultOverlay.classList.add('show');

        } catch (err) {
            console.error("Simulation run failure:", err);
            alert("Simulation processing failed: " + err.message);
        } finally {
            simLaunchBtn.disabled = false;
            simLaunchBtn.textContent = '🚀 Launch Simulation';
        }
    });

    // Close result overlay
    closeOverlayBtn.addEventListener('click', () => {
        resultOverlay.classList.remove('show');

        if (isRotatedState) {
            logoutSession();
        }
    });

    // Copy new rotated password
    copyNewPasswordBtn.addEventListener('click', () => {
        const passVal = rotationNewPassword.textContent;
        navigator.clipboard.writeText(passVal).then(() => {
            const originalText = copyNewPasswordBtn.textContent;
            copyNewPasswordBtn.textContent = '📋 Copied!';
            setTimeout(() => { copyNewPasswordBtn.textContent = originalText; }, 1200);
        });
    });

    // Copy active password in sidebar
    dashCopyPassBtn.addEventListener('click', () => {
        const passVal = dashActivePassword.getAttribute('data-password') || loggedInPassword;
        if (!passVal) return;
        navigator.clipboard.writeText(passVal).then(() => {
            const originalText = dashCopyPassBtn.textContent;
            dashCopyPassBtn.textContent = 'Copied!';
            setTimeout(() => { dashCopyPassBtn.textContent = originalText; }, 1200);
        });
    });

    // ── SESSION WATCH: detect server-side credential rotation ──
    // The portal password can be rotated OUTSIDE a simulation — e.g. an admin
    // presses "Rotate Credential" on the 5173 console after a VPN-login alert,
    // or the live pipeline auto-rotates. Poll Vault for the active password;
    // when it no longer matches the session, lock the workspace and log out.
    async function checkCredentialRotation() {
        if (!loggedInUser || isRotatedState) return;
        try {
            const resp = await fetchWithTimeout(`${baseUrl}/api/auth/user-credential/${loggedInUser}`, 6000);
            if (!resp.ok) return;
            const data = await resp.json();
            if (data.current_password && data.current_password !== loggedInPassword) {
                handleExternalRotation(data.current_password);
            }
        } catch { /* transient — try again next tick */ }
    }
    function startSessionWatch() {
        stopSessionWatch();
        // Check once right away so a brute-force rotation that fired during this
        // very login locks the workspace immediately, not 7s later.
        checkCredentialRotation();
        sessionWatchTimer = setInterval(checkCredentialRotation, 7000);
    }
    function stopSessionWatch() {
        if (sessionWatchTimer) { clearInterval(sessionWatchTimer); sessionWatchTimer = null; }
    }

    function handleExternalRotation(newPassword) {
        stopSessionWatch();
        loggedInPassword = newPassword;
        saveSession();
        sessionStorage.setItem('rotated_user', loggedInUser);
        sessionStorage.setItem('last_rotated_user', loggedInUser);

        // Present the same rotation-lockout overlay used after a simulation
        resultStatusPill.className = 'result-status status-critical';
        resultStatusPill.textContent = 'CREDENTIALS ROTATED';
        resultStatusText.textContent = 'Security rotated your credentials in response to a detected threat.';
        xgbScoreVal.textContent = '—';
        lgbScoreVal.textContent = '—';
        ensembleScoreVal.textContent = '—';
        resultReasonsList.innerHTML = '';
        const li = document.createElement('li');
        li.textContent = '⚠️ Credential rotation triggered by Security Operations (admin approval or VPN/anomaly detection).';
        resultReasonsList.appendChild(li);
        resultReasonsBox.className = 'reasons-box threat';

        rotationNotice.style.display = 'block';
        rotationNewPassword.textContent = newPassword;
        isRotatedState = true;
        resultOverlay.classList.add('show');
    }

    // ── 11. LOGOUT SESSION ──
    function logoutSession() {
        stopSessionWatch();
        clearSession();
        loggedInUser = null;
        loggedInPassword = null;
        userProfile = null;
        loginHistory = null;
        isRotatedState = false;
        sessionDownloads = 0.0;

        // Reset forms
        authForm.reset();
        submitBtn.disabled = false;
        submitBtn.textContent = 'Authorize';
        submitBtn.style.background = '';
        submitBtn.style.opacity = '1';

        // Refresh credential helper list to capture rotated password state
        loadHelperUsers();

        // Transition wrappers
        dashboardWrapper.style.opacity = '0';
        setTimeout(() => {
            dashboardWrapper.style.display = 'none';
            loginWrapper.style.display = 'block';
            loginWrapper.style.opacity = '1';
            
            // Show alert box to notify password change
            showAlert("Session securely rotated. Authenticate with new password.", "success");
        }, 400);
    }

    logoutBtn.addEventListener('click', logoutSession);

    closePreviewBanner.addEventListener('click', () => {
        previewBanner.style.display = 'none';
    });

    // Load helper users list on page load
    loadHelperUsers();

    // ── RESTORE SESSION ON RELOAD ──
    // The dashboard lives in memory, so a plain refresh would drop the user
    // back to the login screen. Re-hydrate from sessionStorage if a session
    // is still active in this tab.
    (function restoreSession() {
        let saved = null;
        try { saved = JSON.parse(sessionStorage.getItem(SESSION_KEY) || 'null'); } catch {}
        if (!saved || !saved.user) return;

        loggedInUser = saved.user;
        loggedInPassword = saved.pw || null;
        prevLoginInfo = saved.prev || null;
        // initializeDashboard re-fetches profile/history; on failure it calls
        // clearSession() and leaves the user on the login screen.
        initializeDashboard(loggedInUser);
    })();
});
