const loginForm = document.getElementById("loginForm");
const message = document.getElementById("message");

loginForm.addEventListener("submit", async function (event) {
    event.preventDefault();

    const email = document.getElementById("email").value;
    const password = document.getElementById("password").value;

    message.textContent = "Logging in...";

    try {
        const response = await fetch("https://trustvault-api-l9hf.onrender.com/login", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                email: email,
                password: password
            })
        });

        const data = await response.json();

        if (response.ok) {
    localStorage.setItem("access_token", data.access_token);

    message.textContent = "Login successful!";

    setTimeout(() => {
        window.location.href = "dashboard.html";
    }, 500);
} else {
            message.textContent = data.detail || "Login failed.";
        }

    } catch (error) {
        console.error(error);
        message.textContent = "Unable to connect to the server.";
    }
});