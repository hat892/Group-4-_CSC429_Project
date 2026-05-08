/* ============================================================
   script.js  –  Client-side validation for Channels by stc
   Provides front-end feedback BEFORE the form is submitted.
   NOTE: Server-side validation in app.py is the real security
   gate; these checks are convenience-only and can be bypassed.
   ============================================================ */


/* ----------------------------------------------------------
   validateStudent()
   Called by the student login form's onsubmit handler.
   Prevents submission when required fields are empty so the
   user gets immediate feedback instead of a server round-trip.
   ---------------------------------------------------------- */
function validateStudent() {
  /* Read the values typed into the login fields */
  let email = document.getElementById("studentEmail").value.trim();
  let pass  = document.getElementById("studentPass").value;

  /* Both fields are required – alert and abort if either is blank */
  if (email === "" || pass === "") {
    alert("Please fill in all fields before logging in.");
    return false; /* returning false cancels the form submission */
  }

  return true; /* validation passed – allow the browser to submit */
}


/* ----------------------------------------------------------
   validateRegister()
   Called by the registration form's onsubmit handler.
   Enforces the same rules that app.py validates on the server:
     • Username  ≥ 8 characters
     • Password  ≥ 8 characters AND contains at least one
       special character (matches OWASP recommendations)
     • A role (Student or Admin) must be selected
   ---------------------------------------------------------- */
function validateRegister() {
  /* Grab current values from the register form fields.
     The name attributes in register.html are "username",
     "password", and "role" – we query them by name here. */
  let username = document.querySelector('input[name="username"]').value.trim();
  let password = document.querySelector('input[name="password"]').value;
  let role     = document.querySelector('input[name="role"]:checked');

  /* --- Username length check -------------------------------- */
  if (username.length < 8) {
    alert("Username must be at least 8 characters long.");
    return false;
  }

  /* --- Password strength check ------------------------------ */
  /* Regex: at least one character from the special-char set   */
  let specialChar = /[!@#$%^&*(),.?":{}|<>]/;
  if (password.length < 8 || !specialChar.test(password)) {
    alert("Password must be at least 8 characters and include at least one special character (e.g. !, @, #).");
    return false;
  }

  /* --- Role selection check --------------------------------- */
  /* The role-toggle in register.html uses radio buttons;
     if none is checked the user hasn't chosen Student/Admin.  */
  if (!role) {
    alert("Please select a role: Student or Admin.");
    return false;
  }

  return true; /* all checks passed – submit the form */
}


/* ----------------------------------------------------------
   validateCoop()
   Called by the COOP application form's onsubmit handler.
   Validates GPA format (Saudi scale: 0.00 – 5.00) and phone
   number format (Saudi mobile: starts with 05, 10 digits).
   ---------------------------------------------------------- */
function validateCoop() {
  let mobile = document.querySelector('input[name="mobile"]').value.trim();
  let gpa    = document.querySelector('input[name="gpa"]').value.trim();

  /* --- Saudi mobile number: must be 10 digits starting 05 -- */
  let mobileRegex = /^05\d{8}$/;
  if (!mobileRegex.test(mobile)) {
    alert("Mobile number must be a valid Saudi number starting with 05 (e.g. 0512345678).");
    return false;
  }

  /* --- GPA: a decimal between 0.00 and 5.00 ----------------- */
  let gpaValue = parseFloat(gpa);
  if (isNaN(gpaValue) || gpaValue < 0 || gpaValue > 5) {
    alert("GPA must be a number between 0.00 and 5.00.");
    return false;
  }

  return true; /* validation passed */
}