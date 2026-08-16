/**
 * Toggles visibility of the password field adjacent to the clicked button.
 */
function togglePassword(btn) {
    const wrapper = btn.closest('.password-wrapper');
    const input = wrapper.querySelector('input');
    const icon = btn.querySelector('.eye-icon');
    if (input.type === 'password') {
        input.type = 'text';
        icon.textContent = '🙈';
        btn.setAttribute('aria-pressed', 'true');
    } else {
        input.type = 'password';
        icon.textContent = '👁';
        btn.setAttribute('aria-pressed', 'false');
    }
}


// Patterns that indicate potential XSS or injection attacks
const XSS_PATTERNS = [
    /<script/i, /javascript:/i, /on\w+\s*=/i, /alert\s*\(/i,
    /confirm\s*\(/i, /prompt\s*\(/i, /document\.(cookie|write)/i,
    /window\.location/i, /eval\s*\(/i, /<iframe/i, /<object/i,
    /vbscript:/i, /expression\s*\(/i
];

const SQL_PATTERNS = [
    /'\s*(or|and)\s*'?\d/i, /;\s*(drop|delete|insert|update|select)/i,
    /--\s/, /\/\*.*\*\//
];

function containsXss(value) {
    return XSS_PATTERNS.some(p => p.test(value));
}

function containsSql(value) {
    return SQL_PATTERNS.some(p => p.test(value));
}

function showClientError(form, message) {
    let errDiv = form.querySelector('#clientError');
    if (!errDiv) {
        errDiv = document.createElement('div');
        errDiv.id = 'clientError';
        errDiv.className = 'alert alert-danger';
        form.insertBefore(errDiv, form.querySelector('button[type=submit]'));
    }
    errDiv.textContent = message;
    errDiv.style.display = 'block';
}

function hideClientError(form) {
    const errDiv = form.querySelector('#clientError');
    if (errDiv) errDiv.style.display = 'none';
}

/**
 * Validates all text/email inputs in a form for XSS and injection.
 * Returns false (blocking submit) if a dangerous pattern is detected.
 */
function validateFormSecurity(form) {
    hideClientError(form);
    const inputs = form.querySelectorAll('input[type=text], input[type=email], input:not([type])');
    for (const input of inputs) {
        const val = input.value;
        if (containsXss(val)) {
            showClientError(form, '⚠️ Potentially dangerous content detected in ' + (input.placeholder || input.name) + '. Please remove script or HTML tags.');
            input.focus();
            return false;
        }
        if (containsSql(val)) {
            showClientError(form, '⚠️ Invalid characters detected. SQL-like patterns are not allowed.');
            input.focus();
            return false;
        }
    }
    return true;
}

/**
 * Extended validation for the registration form:
 * username format, password strength, confirmation match.
 */
function validateRegisterForm(form) {
    if (!validateFormSecurity(form)) return false;

    const username = form.querySelector('#Username');
    const email = form.querySelector('#Email');
    const password = form.querySelector('#Password');
    const confirm = form.querySelector('#ConfirmPassword');

    if (username && !/^[a-zA-Z0-9_]{3,50}$/.test(username.value)) {
        showClientError(form, '⚠️ Username must be 3–50 characters: letters, numbers, and underscores only.');
        username.focus();
        return false;
    }

    if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.value)) {
        showClientError(form, '⚠️ Please enter a valid email address.');
        email.focus();
        return false;
    }

    if (password && password.value.length < 8) {
        showClientError(form, '⚠️ Password must be at least 8 characters.');
        password.focus();
        return false;
    }

    if (password && confirm && password.value !== confirm.value) {
        showClientError(form, '⚠️ Passwords do not match.');
        confirm.focus();
        return false;
    }

    return true;
}
