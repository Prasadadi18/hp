document.addEventListener('DOMContentLoaded', () => {
    const authForm = document.getElementById('authForm');
    const btn = document.getElementById('submitBtn');
    const alertBox = document.getElementById('alertBox');
    const alertText = document.getElementById('alertText');
    const alertIcon = document.getElementById('alertIcon');
    const apiUrlInput = document.getElementById('apiUrl');
    
    const formTitle = document.getElementById('formTitle');
    const formSubtitle = document.getElementById('formSubtitle');
    const deptGroup = document.getElementById('deptGroup');
    const passGroup = document.getElementById('passGroup');
    const passwordInput = document.getElementById('password');
    const toggleMode = document.getElementById('toggleMode');
    const toggleText = document.getElementById('toggleText');

    let isLoginMode = true;

    // Helper: SVG Icons for alerts
    const iconSuccess = `<path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline>`;
    const iconError = `<circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line>`;

    function applyTransition(element, callback) {
        element.style.opacity = '0';
        element.style.transform = 'translateY(10px)';
        setTimeout(() => {
            callback();
            element.style.opacity = '1';
            element.style.transform = 'translateY(0)';
        }, 300);
    }

    toggleMode.addEventListener('click', (e) => {
        e.preventDefault();
        isLoginMode = !isLoginMode;
        
        // Smooth form transition
        authForm.style.opacity = '0';
        
        setTimeout(() => {
            if (isLoginMode) {
                formTitle.textContent = 'Secure Gateway';
                formSubtitle.textContent = 'Authenticate to access the enterprise network';
                deptGroup.style.display = 'none';
                passGroup.style.display = 'block';
                passwordInput.required = true;
                btn.textContent = 'Authorize';
                toggleText.innerHTML = 'New employee? <a class="toggle-link" id="toggleMode">Request access</a>';
            } else {
                formTitle.textContent = 'Access Request';
                formSubtitle.textContent = 'Request clearance for the enterprise portal';
                deptGroup.style.display = 'block';
                passGroup.style.display = 'none';
                passwordInput.required = false;
                btn.textContent = 'Submit Request';
                toggleText.innerHTML = 'Already authorized? <a class="toggle-link" id="toggleMode">Sign in</a>';
            }
            
            authForm.style.opacity = '1';
            
            // Re-attach listener to newly created link
            document.getElementById('toggleMode').addEventListener('click', (e) => {
                e.preventDefault();
                toggleMode.click();
            });
        }, 300);
    });

    function showAlert(message, type) {
        alertText.textContent = message;
        alertIcon.innerHTML = type === 'success' ? iconSuccess : iconError;
        alertBox.className = `status-alert alert-${type} show`;
    }

    function hideAlert() {
        alertBox.className = 'status-alert';
    }

    authForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        hideAlert();
        
        const username = document.getElementById('username').value.trim();
        const password = document.getElementById('password').value;
        const department = document.getElementById('department').value.trim();
        const baseUrl = (apiUrlInput && apiUrlInput.value) ? apiUrlInput.value.replace(/\/$/, "") : window.location.origin; 

        if (!username || (isLoginMode && !password) || (!isLoginMode && !department)) {
            showAlert('Please complete all required fields.', 'error');
            return;
        }

        btn.disabled = true;
        btn.textContent = isLoginMode ? 'Verifying...' : 'Processing...';
        btn.style.opacity = '0.7';

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
                
                btn.textContent = isLoginMode ? 'Access Granted' : 'Request Submitted';
                btn.style.background = 'linear-gradient(135deg, #01A982 0%, #006644 100%)';
                
                if (!isLoginMode) {
                    setTimeout(() => {
                        isLoginMode = false;
                        toggleMode.click(); 
                    }, 2500);
                }
                
                setTimeout(() => {
                    authForm.reset();
                    btn.disabled = false;
                    btn.textContent = isLoginMode ? 'Authorize' : 'Submit Request';
                    btn.style.background = '';
                    btn.style.opacity = '1';
                    hideAlert();
                }, 3500);
            } else {
                showAlert(data.detail || data.message || 'Authentication failed', 'error');
                btn.disabled = false;
                btn.textContent = isLoginMode ? 'Authorize' : 'Submit Request';
                btn.style.opacity = '1';
            }
        } catch (error) {
            console.error(error);
            showAlert('Connection securely aborted. Target unreachable.', 'error');
            btn.disabled = false;
            btn.textContent = isLoginMode ? 'Authorize' : 'Submit Request';
            btn.style.opacity = '1';
        }
    });
});
