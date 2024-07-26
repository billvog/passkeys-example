import React from "react";
import "./App.css";
import { fido2Create, fido2Get } from "@ownid/webauthn";

function App() {
  const [username, setUsername] = React.useState("");

  async function register() {
    const publicKey = await fetch("/register/start", {
      body: JSON.stringify({ username }),
      headers: { "Content-Type": "application/json" },
      method: "POST",
    }).then((response) => response.json());

    const fidoData = await fido2Create(publicKey, username);

    const response = await fetch("/register/finish", {
      body: JSON.stringify(fidoData),
      headers: { "Content-Type": "application/json" },
      method: "POST",
    }).then((response) => response.json());

    if (response.error || !response.success) {
      alert(response.error || "Registration failed");
      return;
    }

    alert("Registration successful");
  }

  async function login() {
    const response = await fetch("/login/start", {
      body: JSON.stringify({ username }),
      headers: { "Content-Type": "application/json" },
      method: "POST",
    }).then((response) => response.json());

    if (response.error) {
      alert(response.error);
      return;
    }

    const options = response as PublicKeyCredentialRequestOptions;
    const assertion = await fido2Get(options, username);

    const loginResponse = await fetch("/login/finish", {
      body: JSON.stringify(assertion),
      headers: { "Content-Type": "application/json" },
      method: "POST",
    }).then((response) => response.json());

    if (loginResponse.error || !loginResponse.success) {
      alert(loginResponse.error || "Login failed");
      return;
    }

    alert("Login successful");
  }

  return (
    <main>
      <h1>Passkeys Example</h1>
      <p className="input-container">
        <label htmlFor="username">Username</label>
        <input
          id="username"
          type="text"
          placeholder="Username"
          onChange={(event) => setUsername(event.currentTarget.value)}
        />
      </p>
      <div className="button-group">
        <button onClick={register}>Register</button>
        <button onClick={login}>Login</button>
      </div>
    </main>
  );
}

export default App;
