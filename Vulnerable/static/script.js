function validateStudent() {
let email = document.getElementById("studentEmail").value;
let pass = document.getElementById("studentPass").value;

```
if (email === "" || pass === "") {
    alert("Please fill all fields");
    return false;
}

return true;
```

}






function validateRegister() {
    let username = document.getElementById("regUser").value;
    let password = document.getElementById("regPass").value;
    let role = document.querySelector('input[name="role"]:checked');

    if (username.length < 8) {
        alert("Username must be at least 8 characters");
        return false;
    }

    let specialChar = /[!@#$%^&*(),.?":{}|<>]/;
    if (password.length < 8 || !specialChar.test(password)) {
        alert("Password must be at least 8 characters and include a special character");
        return false;
    }

    if (!role) {
        alert("Please select Student or Admin");
        return false;
    }

   
    return true;
}