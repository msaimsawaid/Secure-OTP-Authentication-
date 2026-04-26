# Quality Assurance & Security Test Report

## 1. Functional Testing Summary
**Date:** November 29, 2025
**Tester:** Automated/Manual Suite

| Test Case ID | Description | Input Data | Expected Result | Actual Result | Status |
|---|---|---|---|---|---|
| **FUNC-01** | Valid OTP Request | Valid email format | OTP sent to email; UI updates to Step 2 | OTP Received | ✅ PASS |
| **FUNC-02** | Invalid Email Format | `user@domain` (no .com) | Error message displayed | Error "Invalid Email" | ✅ PASS |
| **FUNC-03** | Valid OTP Verify | Correct 6-digit code | Success message; Token returned | Token Received | ✅ PASS |
| **FUNC-04** | Invalid OTP Verify | Wrong 6-digit code | Error message; Attempt counter +1 | "Invalid OTP" shown | ✅ PASS |
| **FUNC-05** | Expired OTP | Code older than 3 mins | Error "OTP Expired" | "OTP Expired" | ✅ PASS |
| **FUNC-06** | Rate Limiting | >5 requests in 15m | 429 Too Many Requests | 429 Error | ✅ PASS |

## 2. Security Testing (Penetration & Vulnerability)

### A. Injection Attacks (SQLi / Command Injection)
* **Test:** Attempted input: `' OR 1=1 --` in email field.
* **Result:** System rejected input via Regex validation (`re.match`). No database errors exposed.
* **Status:** ✅ SECURED

### B. Cross-Site Scripting (XSS)
* **Test:** Attempted input: `<script>alert('XSS')</script>` in email field.
* **Result:** Input sanitized on backend; Browser did not execute script.
* **Status:** ✅ SECURED

### C. Brute Force Protection
* **Test:** Scripted 100 rapid verification attempts.
* **Result:** Account locked after 3rd failed attempt. User forced to wait 15 minutes.
* **Status:** ✅ SECURED

### D. Session Management
* **Test:** Checked browser cookies.
* **Result:** Cookies set with `HttpOnly` and `SameSite=Lax`. JavaScript cannot access session ID.
* **Status:** ✅ SECURED