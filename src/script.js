/**
 * FILE-LEVEL COMMENT
 * Project: Secure OTP Authentication System
 * File: script.js
 * Purpose: Handles client-side logic, API communication, and UI state management.
 * Security Implementation:
 * - Performs initial client-side validation before server transmission.
 * - Manages secure timers for OTP expiry and account lockout visibility.
 * - Uses 'credentials: include' to ensure secure session cookies are handled correctly.
 * - Implements generic error handling to avoid leaking technical details to the user.
 */
// API Configuration
const API_BASE_URL = 'http://localhost:5000';
const OTP_EXPIRY_SECONDS = 180;

// DOM Elements
const step1 = document.getElementById('step1');
const step2 = document.getElementById('step2');
const lockoutMessage = document.getElementById('lockoutMessage');

const requestOtpForm = document.getElementById('requestOtpForm');
const emailInput = document.getElementById('email');
const emailError = document.getElementById('emailError');
const requestBtn = document.getElementById('requestBtn');
const requestLoading = document.getElementById('requestLoading');
const requestSuccess = document.getElementById('requestSuccess');
const requestError = document.getElementById('requestError');

const verifyOtpForm = document.getElementById('verifyOtpForm');
const otpInput = document.getElementById('otp');
const otpError = document.getElementById('otpError');
const otpTimer = document.getElementById('otpTimer');
const verifyBtn = document.getElementById('verifyBtn');
const verifyLoading = document.getElementById('verifyLoading');
const verifySuccess = document.getElementById('verifySuccess');
const verifyError = document.getElementById('verifyError');
const backBtn = document.getElementById('backBtn');
const attemptCounter = document.getElementById('attemptCounter');
const attemptText = document.getElementById('attemptText');
const lockoutTimer = document.getElementById('lockoutTimer');

// State Management
let userEmail = '';
let otpStartTime = null;
let otpTimerInterval = null;
let lockoutEndTime = null;
let lockoutInterval = null;

// ============================================================================
// REQUEST OTP FUNCTIONALITY
// ============================================================================
// FUNCTION: requestOtpForm Event Listener
// What it does: Captures user email and initiates the OTP request to the backend.
// Security Checks: 
//   - Client-side validation: Prevents sending obviously malformed emails to the API.
//   - UI State Management: Disables buttons during transit to prevent rapid-click DoS.
// Inputs: User email from 'emailInput' field.
// Outputs: Transitions UI to Step 2 (Verification) or displays server-side error.
// ============================================================================
requestOtpForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    emailError.textContent = '';
    requestError.innerHTML = '';
    requestSuccess.style.display = 'none';

    userEmail = emailInput.value.trim();

    // Validate email format
    if (!isValidEmail(userEmail)) {
        emailError.textContent = 'Please enter a valid email address';
        return;
    }

    // Show loading state
    requestBtn.style.display = 'none';
    requestLoading.style.display = 'flex';

    try {
        const response = await fetch(`${API_BASE_URL}/request-otp`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ email: userEmail }),
            credentials: 'include', // Include cookies for session management
        });

        const data = await response.json();

        if (!response.ok) {
            handleRequestOtpError(response.status, data);
            requestBtn.style.display = 'block';
            requestLoading.style.display = 'none';
            return;
        }

        // Success - Move to step 2
        requestSuccess.style.display = 'block';
        console.log('OTP request successful:', data);
        setTimeout(() => {
            step1.classList.remove('active');
            step2.classList.add('active');
            otpInput.focus();
            startOtpTimer();
        }, 1000);

    } catch (error) {
        console.error('Error requesting OTP:', error);
        requestError.innerHTML = `<strong>Connection Error:</strong> ${error.message || 'Unable to connect to server. Please check if Flask backend is running on http://localhost:5000'}`;
        requestBtn.style.display = 'block';
        requestLoading.style.display = 'none';
    }
});

// ============================================================================
// VERIFY OTP FUNCTIONALITY
// ============================================================================
// FUNCTION: verifyOtpForm Event Listener
// What it does: Captures the 6-digit OTP and submits it for server-side verification.
// Security Checks: 
//   - Format Enforcement: Ensures only 6-digit numeric codes are sent (STRIDE: T).
//   - Session Integrity: Includes credentials (cookies) in the fetch request.
// Inputs: 6-digit numeric OTP and normalized email string.
// Outputs: Displays authentication token on success or handles lockout/failure.
// ============================================================================
verifyOtpForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    otpError.textContent = '';
    verifyError.innerHTML = '';
    verifySuccess.style.display = 'none';
    attemptCounter.style.display = 'none';

    const otp = otpInput.value.trim();

    // Validate OTP format
    if (!otp || otp.length !== 6 || !/^\d+$/.test(otp)) {
        otpError.textContent = 'Please enter a 6-digit OTP';
        return;
    }

    // Show loading state
    verifyBtn.style.display = 'none';
    verifyLoading.style.display = 'flex';

    try {
        const response = await fetch(`${API_BASE_URL}/verify-otp`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ email: userEmail, otp: otp }),
            credentials: 'include',
        });

        const data = response.json();

        if (!response.ok) {
            await handleVerifyOtpError(response.status, await data);
            verifyBtn.style.display = 'block';
            verifyLoading.style.display = 'none';
            return;
        }

        const responseData = await data;

        // ADDED FOR RBAC VERIFICATION
        console.log('RBAC Response Data:', responseData);
        // Success
        verifySuccess.style.display = 'block';
        document.getElementById('tokenDisplay').textContent = `Token: ${responseData.token}`;
        
        // Clear the form
        otpInput.value = '';
        clearInterval(otpTimerInterval);
        
        // Show success for 3 seconds then redirect
        setTimeout(() => {
            showSuccessScreen();
        }, 1500);

    } catch (error) {
        console.error('Error verifying OTP:', error);
        verifyError.innerHTML = `<strong>Error:</strong> Unable to verify OTP. Please try again.`;
        verifyBtn.style.display = 'block';
        verifyLoading.style.display = 'none';
    }
});

// ============================================================================
// BACK BUTTON
// ============================================================================

backBtn.addEventListener('click', () => {
    // Reset step 2
    otpInput.value = '';
    otpError.textContent = '';
    verifyError.innerHTML = '';
    verifySuccess.style.display = 'none';
    attemptCounter.style.display = 'none';
    verifyBtn.style.display = 'block';
    verifyLoading.style.display = 'none';

    // Clear timer
    clearInterval(otpTimerInterval);

    // Go back to step 1
    step2.classList.remove('active');
    step1.classList.add('active');
    emailInput.focus();
});

// ============================================================================
// OTP TIMER
// ============================================================================
// FUNCTION: startOtpTimer
// What it does: Manages the client-side countdown for OTP validity.
// Security Checks: 
//   - Visual Enforcement: Disables input fields immediately upon 3-minute expiry 
//     to prevent stale data submission (STRIDE: I).
// Inputs: Global constant OTP_EXPIRY_SECONDS.
// Outputs: Live UI updates to the timer element.
// ============================================================================
function startOtpTimer() {
    otpStartTime = Date.now();
    otpTimerInterval = setInterval(() => {
        const elapsed = Math.floor((Date.now() - otpStartTime) / 1000);
        const remaining = OTP_EXPIRY_SECONDS - elapsed;

        if (remaining <= 0) {
            clearInterval(otpTimerInterval);
            otpTimer.textContent = 'Expired';
            otpTimer.classList.add('expired');
            otpInput.disabled = true;
            verifyBtn.disabled = true;
            otpError.textContent = 'OTP has expired. Please request a new one.';
        } else {
            const minutes = Math.floor(remaining / 60);
            const seconds = remaining % 60;
            otpTimer.textContent = `${minutes}:${seconds < 10 ? '0' : ''}${seconds}`;
            
            if (remaining <= 30) {
                otpTimer.classList.add('expired');
            }
        }
    }, 1000);
}

// ============================================================================
// LOCKOUT TIMER
// ============================================================================
// FUNCTION: startLockoutTimer
// What it does: Enforces a UI-level block when an account is locked.
// Security Checks: 
//   - DoS Mitigation: Hides the forms entirely during the 15-minute penalty 
//     period to discourage further brute-force attempts (STRIDE: D).
// Inputs: lockoutMinutes (passed from backend response).
// Outputs: Displays lockout alert and countdown.
// ============================================================================
function startLockoutTimer(lockoutMinutes) {
    lockoutEndTime = Date.now() + (lockoutMinutes * 60 * 1000);
    
    step1.style.display = 'none';
    step2.style.display = 'none';
    lockoutMessage.style.display = 'block';

    lockoutInterval = setInterval(() => {
        const remaining = Math.max(0, Math.floor((lockoutEndTime - Date.now()) / 1000));
        
        if (remaining <= 0) {
            clearInterval(lockoutInterval);
            lockoutMessage.style.display = 'none';
            step1.style.display = 'block';
            step1.classList.add('active');
            resetForm();
        } else {
            const minutes = Math.floor(remaining / 60);
            const seconds = remaining % 60;
            lockoutTimer.textContent = `${minutes}m ${seconds}s`;
        }
    }, 1000);
}

// ============================================================================
// ERROR HANDLING
// ============================================================================
// FUNCTION: handleRequestOtpError 
// What it does: Parses backend error codes (400, 403, 429, 500) into user feedback.
// Security Checks: 
//   - Information Disclosure: Converts technical API errors into generic messages 
//     to prevent leaking server logic or user existence (STRIDE: I).
// Inputs: HTTP Status Code and JSON error data.
// Outputs: Specific UI error alerts or trigger for lockout timers.
// ============================================================================
function handleRequestOtpError(status, data) {
    switch (status) {
        case 400:
            emailError.textContent = data.error || 'Invalid email address';
            break;
        case 403:
            // Account locked
            startLockoutTimer(15); // LOCKOUT_DURATION from backend
            break;
        case 429:
            requestError.innerHTML = `<strong>Rate Limit:</strong> ${data.error || 'Too many requests. Please wait before trying again.'}`;
            break;
        case 500:
            requestError.innerHTML = `<strong>Server Error:</strong> ${data.error || 'Failed to send OTP. Check backend email configuration (Gmail credentials must be configured in app.py)'}`; 
            console.error('Backend error details:', data);
            break;
        default:
            requestError.innerHTML = `<strong>Error (${status}):</strong> ${data.error || 'An error occurred. Please try again.'}`;
    }
}
// ============================================================================
// FUNCTION:  handleVerifyOtpError
// What it does: Parses backend error codes (400, 403, 429, 500) into user feedback.
// Security Checks: 
//   - Information Disclosure: Converts technical API errors into generic messages 
//     to prevent leaking server logic or user existence (STRIDE: I).
// Inputs: HTTP Status Code and JSON error data.
// Outputs: Specific UI error alerts or trigger for lockout timers.
// ============================================================================
async function handleVerifyOtpError(status, data) {
    switch (status) {
        case 400:
            otpError.textContent = data.error || 'Invalid OTP';
            break;
        case 401:
            otpError.textContent = data.error || 'Invalid OTP';
            break;
        case 403:
            if (data.error.includes('locked')) {
                startLockoutTimer(15); // LOCKOUT_DURATION from backend
            } else {
                verifyError.innerHTML = `<strong>Locked:</strong> ${data.error}`;
            }
            break;
        case 404:
            verifyError.innerHTML = '<strong>Error:</strong> User not found. Please request OTP again.';
            break;
        default:
            verifyError.innerHTML = `<strong>Error (${status}):</strong> ${data.error || 'An error occurred. Please try again.'}`;
    }

    // Show attempt counter if OTP verification failed (not locked)
    if (status === 401 && data.error.includes('Invalid')) {
        const remaining = 3 - (data.attempts || 0);
        if (remaining > 0) {
            attemptText.textContent = `Remaining attempts: ${remaining}`;
            attemptCounter.style.display = 'block';
        }
    }
}

// ============================================================================
// VALIDATION
// ============================================================================
// FUNCTION: isValidEmail
// What it does: Client-side Regex check for email structure.
// Security Checks: Sanitizes input before it reaches the fetch API.
// Inputs: Email string | Outputs: Boolean.
// ============================================================================
function isValidEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

// Only allow numeric input in OTP field
otpInput.addEventListener('keypress', (e) => {
    if (!/[0-9]/.test(e.key)) {
        e.preventDefault();
    }
});

// Auto-focus to verify button when 6 digits are entered
otpInput.addEventListener('input', (e) => {
    if (e.target.value.length === 6) {
        verifyBtn.focus();
    }
});

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================
// FUNCTION: resetForm
// What it does: Clears all sensitive inputs and reset the UI to its initial state.
// Security Checks: Ensures that sensitive data (like used OTPs or errors) 
//   is purged from the DOM when the user navigates back.
// Inputs: None | Outputs: Cleared UI fields.
// ============================================================================
function resetForm() {
    emailInput.value = '';
    otpInput.value = '';
    emailError.textContent = '';
    otpError.textContent = '';
    requestError.innerHTML = '';
    verifyError.innerHTML = '';
    requestSuccess.style.display = 'none';
    verifySuccess.style.display = 'none';
    attemptCounter.style.display = 'none';
    requestBtn.style.display = 'block';
    requestLoading.style.display = 'none';
    verifyBtn.style.display = 'block';
    verifyLoading.style.display = 'none';
    step1.classList.add('active');
    step2.classList.remove('active');
}

function showSuccessScreen() {
    // Optional: You can add a redirect here
    console.log('Authentication successful!');
    // Example: window.location.href = '/dashboard';
}

// Initialize - Focus on email input
window.addEventListener('load', () => {
    emailInput.focus();
});

// CORS-friendly error logging
window.addEventListener('error', (event) => {
    console.error('Error:', event.error);
});
