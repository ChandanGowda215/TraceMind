const authForm = document.getElementById("auth-form");
authForm?.addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = authForm.querySelector("button");
  const error = document.getElementById("form-error");
  button.disabled = true;
  button.textContent = "Please wait…";
  error.textContent = "";
  const form = new FormData(authForm);
  try {
    const response = await fetch(authForm.dataset.endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: form.get("email"), password: form.get("password") })
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.detail || "Unable to sign in.");
    location.href = "/app";
  } catch (reason) {
    error.textContent = reason.message || "The server could not be reached. Is Trace Mind running?";
    button.disabled = false;
    button.innerHTML = authForm.dataset.endpoint.endsWith("signup") ? "Create account <span>→</span>" : "Sign in <span>→</span>";
  }
});
