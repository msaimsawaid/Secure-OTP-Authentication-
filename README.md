Based on the requirements for **Assignment 3**, your `README.md` needs to be updated to reflect the new **Folder Structure**, the transition to **Environment Variables**, and the **Role-Based Access Control (RBAC)** implementation.

Here is the updated, professionally formatted `README.md` for your final submission:

---

# Secure OTP Authentication System (SSD Assignment 3)

## Description
This project is a secure implementation of a One-Time Password (OTP) authentication system, developed as part of the **Software Security Design (SSD)** course. It translates a UMLsec-based secure design into a working prototype using defensive programming and secure coding principles. The system provides a robust authentication and authorization flow, protecting against common web vulnerabilities identified in the **STRIDE** threat model.

## Security Features Implemented
The following security controls have been integrated into the codebase to satisfy the SSD rubric:

* **Authentication Security**: Cryptographically secure 6-digit OTP generation using the `secrets` module.
* **Password Hashing**: OTPs are never stored in plaintext; they are hashed using **PBKDF2-HMAC-SHA256** with 100,000 iterations.
* **Authorization (RBAC)**: Implements Role-Based Access Control to distinguish between `admin` and `user` roles based on authenticated identity.
* **Input Validation**: Strict server-side Regular Expression (Regex) validation for all email and OTP inputs.
* **DoS Protection**: Implements sliding-window **Rate Limiting** (5 requests/15 mins) and **Account Lockout** (3 failed attempts/15 mins).
* **Secure Session Handling**: Cookies are hardened with `HttpOnly`, `Secure`, and `SameSite=Lax` flags.
* **API Security & Headers**: Hardened API responses with `Content-Security-Policy`, `X-Frame-Options: DENY`, and `X-Content-Type-Options: nosniff`.
* **No Hardcoded Secrets**: All sensitive configuration is handled via environment variables.

## Project Structure
```text
SSD_Assignment3_MuhammadSaimSawaid/
├── src/                    # Source Code
│   ├── app.py              # Backend logic with RBAC & STRIDE mitigations
│   └── static/             # Frontend UI files
│       ├── index.html
│       ├── script.js
│       └── styles.css
├── docs/                   # Documentation
│   ├── THREAT_MODEL.md     # STRIDE Analysis
│   └── SAST_REPORT.md      # Static Analysis Security Testing
├── .env                    # Environment Variables (Private)
├── .env.example            # Template for setup
├── requirements.txt        # Python Dependencies
└── README.md               # Mandatory setup and project guide
```

## Dependencies
The project requires the following Python libraries (documented in `requirements.txt`):
* `Flask`: Web framework
* `Flask-Mail`: SMTP integration
* `Flask-CORS`: Cross-Origin Resource Sharing management
* `python-dotenv`: Environment variable management
* `cryptography` & `pyopenssl`: Secure communication

## Environment Variables
Create a `.env` file in the root directory and configure the following variables (refer to `.env.example`):
```text
MAIL_USERNAME=your_email@gmail.com
MAIL_PASSWORD=your_app_password
MAIL_DEFAULT_SENDER=your_email@gmail.com
SECRET_KEY=generate_a_secure_hex_string
```

## Setup Instructions
1.  **Clone the Repository**:
    ```bash
    git clone <repository-url>
    cd SSD_Assignment3_MuhammadSaimSawaid
    ```
2.  **Create a Virtual Environment**:
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate
    ```
3.  **Install Dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

## How to Run Project
To run the application locally for testing:

1.  **Start the Backend (Flask)**:
    ```bash
    python src/app.py
    ```
    *The API will be available at `http://localhost:5000`.*

2.  **Start the Frontend (HTTP Server)**:
    In a new terminal:
    ```bash
    cd src/static
    python -m http.server 8000
    ```
    *Open your browser and navigate to `http://localhost:8000`.*

---
