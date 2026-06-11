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

    // Dashboard View Elements
    const dashboardWrapper = document.getElementById('dashboardWrapper');
    const userAvatar = document.getElementById('userAvatar');
    const userNameDisplay = document.getElementById('userNameDisplay');
    const userRoleDisplay = document.getElementById('userRoleDisplay');
    const userHomeRegionDisplay = document.getElementById('userHomeRegionDisplay');
    const userStatusDisplay = document.getElementById('userStatusDisplay');
    const dashActivePassword = document.getElementById('dashActivePassword');
    const dashCopyPassBtn = document.getElementById('dashCopyPassBtn');
    const logoutBtn = document.getElementById('logoutBtn');

    // Workspaces
    const workspaceDeveloper = document.getElementById('workspaceDeveloper');
    const workspaceFinance = document.getElementById('workspaceFinance');
    const workspaceHR = document.getElementById('workspaceHR');
    const workspaceSales = document.getElementById('workspaceSales');
    const workspaceAdmin = document.getElementById('workspaceAdmin');

    // Simulation Form Elements
    const simForm = document.getElementById('simForm');
    const simHour = document.getElementById('simHour');
    const simRegion = document.getElementById('simRegion');
    const simDownload = document.getElementById('simDownload');
    const simFailed = document.getElementById('simFailed');
    const simTravel = document.getElementById('simTravel');
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
    let availableUsers = [];
    let isRotatedState = false; // Triggers logout on result dialog close

    // Alert icons
    const iconSuccess = `<path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline>`;
    const iconError = `<circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line>`;

    const baseUrl = window.location.origin;

    // ── 3. INITIALIZATION ──
    async function loadHelperUsers() {
        try {
            const response = await fetch(`${baseUrl}/api/auth/users`);
            if (!response.ok) throw new Error("Failed to load user catalog");
            
            const users = await response.json();
            availableUsers = users;
            
            userSelector.innerHTML = '<option value="">-- Select a User to Autofill --</option>';
            users.forEach(u => {
                const opt = document.createElement('option');
                opt.value = u.user_id;
                opt.textContent = `${u.user_id} (${u.role})`;
                userSelector.appendChild(opt);
            });
        } catch (e) {
            console.error("Helper loader failed:", e);
            userSelector.innerHTML = '<option value="">Failed to load user data</option>';
        }
    }

    loadHelperUsers();

    // User selector change listener
    userSelector.addEventListener('change', async () => {
        const selectedId = userSelector.value;
        if (!selectedId) {
            helperInfo.style.display = 'none';
            return;
        }

        try {
            // Fetch profile and credential
            const [profileResp, credResp] = await Promise.all([
                fetch(`${baseUrl}/api/auth/user-profile/${selectedId}`),
                fetch(`${baseUrl}/api/auth/user-credential/${selectedId}`)
            ]);

            if (!profileResp.ok || !credResp.ok) throw new Error("Profile loading failed");

            const profile = await profileResp.json();
            const credentials = await credResp.json();

            helperRole.textContent = profile.role;
            helperRegion.textContent = profile.home_region;
            helperPassword.textContent = credentials.current_password;
            helperInfo.style.display = 'flex';
        } catch (e) {
            console.error("Error loading user helper data", e);
            helperInfo.style.display = 'none';
        }
    });

    // Copy and autofill credentials
    copyPasswordBtn.addEventListener('click', () => {
        const selectedId = userSelector.value;
        const passVal = helperPassword.textContent;
        if (!selectedId || !passVal) return;

        usernameInput.value = selectedId;
        passwordInput.value = passVal;

        navigator.clipboard.writeText(passVal).then(() => {
            const originalText = copyPasswordBtn.textContent;
            copyPasswordBtn.textContent = '📋 Autofilled!';
            setTimeout(() => {
                copyPasswordBtn.textContent = originalText;
            }, 1500);
        });
    });

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

    // ── 4. ACCESS / LOGIN SUBMISSION ──
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
                    // Successful Auth - Initialize Dashboard state
                    loggedInUser = data.user_id || username;
                    loggedInPassword = password;
                    
                    // Fetch user baseline profile details
                    await initializeDashboard(loggedInUser);
                } else {
                    setTimeout(() => {
                        isLoginMode = false;
                        toggleMode.click();
                        authForm.reset();
                    }, 2000);
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

            // Setup Profile sidebar
            userAvatar.textContent = userId.slice(0, 3) === 'USR' ? userId.slice(4, 6) : userId.slice(0, 1).toUpperCase();
            userNameDisplay.textContent = userId;
            userRoleDisplay.textContent = userProfile.role;
            userHomeRegionDisplay.textContent = userProfile.home_region;
            userStatusDisplay.textContent = 'Active';
            dashActivePassword.textContent = credentials.current_password;

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

            // Setup Sliders
            simHour.value = userProfile.base_login_hour ? Math.round(userProfile.base_login_hour) : 9;
            simRegion.value = userProfile.home_region || 'US-East';
            simDownload.value = userProfile.avg_daily_downloads_mb ? Math.round(userProfile.avg_daily_downloads_mb) : 10;
            simFailed.value = 0;
            simTravel.checked = false;
            simVpn.checked = false;

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

        } catch (e) {
            console.error("Dashboard initialize error:", e);
            showAlert("Error preparing simulation session profile data.", "error");
            submitBtn.disabled = false;
            submitBtn.textContent = 'Authorize';
            submitBtn.style.background = '';
        }
    }

    // ── 6. SLIDERS & INTERACTIVE BEHAVIOR ──
    function updateSlidersUI() {
        // Hour formatting
        const hr = parseInt(simHour.value);
        const padHr = hr.toString().padStart(2, '0');
        hourVal.textContent = `${padHr}:00`;
        
        regionVal.textContent = simRegion.value;
        downloadVal.textContent = `${simDownload.value} MB`;
        failedVal.textContent = simFailed.value;
    }

    // Slider inputs
    simHour.addEventListener('input', () => { updateSlidersUI(); runLiveAnomalyCheck(); });
    simRegion.addEventListener('change', () => { updateSlidersUI(); runLiveAnomalyCheck(); });
    simDownload.addEventListener('input', () => { updateSlidersUI(); runLiveAnomalyCheck(); });
    simFailed.addEventListener('input', () => { updateSlidersUI(); runLiveAnomalyCheck(); });
    simTravel.addEventListener('change', runLiveAnomalyCheck);
    simVpn.addEventListener('change', runLiveAnomalyCheck);

    // Interactive downloads from Finance page
    document.querySelectorAll('.file-download-trigger').forEach(btn => {
        btn.addEventListener('click', () => {
            const size = parseInt(btn.getAttribute('data-size'));
            simDownload.value = size;
            updateSlidersUI();
            runLiveAnomalyCheck();
            
            // Highlight simulation panel
            simDownload.style.transform = 'scale(1.05)';
            setTimeout(() => { simDownload.style.transform = 'scale(1)'; }, 300);
        });
    });

    // ── 7. LIVE ANOMALY COMPOSER ──
    function runLiveAnomalyCheck() {
        if (!userProfile) return;

        const selHour = parseInt(simHour.value);
        const selRegion = simRegion.value;
        const selDownload = parseFloat(simDownload.value);
        const selFailed = parseInt(simFailed.value);
        const isTravel = simTravel.checked;
        const isVpn = simVpn.checked;

        // Check hour deviation
        const baseHour = userProfile.base_login_hour || 9;
        const isShift = userProfile.is_shift_worker || false;
        let diff = Math.abs(selHour - baseHour);
        if (diff > 12) diff = 24 - diff; // account for hourly circle
        
        const anomalousHour = !isShift && (selHour < 6 || selHour > 22 || diff > 4);
        if (anomalousHour) {
            badgeTime.className = 'indicator-badge anomalous';
            badgeTime.textContent = `🔴 Off-Hours Access (${selHour}:00)`;
        } else {
            badgeTime.className = 'indicator-badge';
            badgeTime.textContent = '🟢 Access Time Normal';
        }

        // Check geo region
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

        // Impossible travel
        if (isTravel) {
            badgeTravel.className = 'indicator-badge anomalous';
            badgeTravel.textContent = '🔴 Impossible Travel Detected';
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

    // ── 8. SUBMIT SIMULATION ──
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
            failed_attempts: parseInt(simFailed.value),
            impossible_travel: simTravel.checked,
            is_vpn: simVpn.checked
        };

        try {
            const response = await fetch(`${baseUrl}/api/auth/simulate`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(body)
            });

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
            } else {
                rotationNotice.style.display = 'none';
                isRotatedState = false;
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
            // Force user to log out since their password rotated, confirming lockout flow
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
        const passVal = dashActivePassword.textContent;
        navigator.clipboard.writeText(passVal).then(() => {
            const originalText = dashCopyPassBtn.textContent;
            dashCopyPassBtn.textContent = 'Copied!';
            setTimeout(() => { dashCopyPassBtn.textContent = originalText; }, 1200);
        });
    });

    // ── 9. LOGOUT SESSION ──
    function logoutSession() {
        loggedInUser = null;
        loggedInPassword = null;
        userProfile = null;
        isRotatedState = false;

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
});
