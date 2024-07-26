import { fido2Create, fido2Get } from "@ownid/webauthn";
import React from "react";
import "./App.css";

function App() {
  const [token, setToken] = React.useState<string>();
  const [username, setUsername] = React.useState("");

  const [currentUser, setCurrentUser] = React.useState<string | null>(null);

  // On token change, fetch user data
  React.useEffect(() => {
    if (!token) {
      setCurrentUser(null);
      return;
    }

    (async () => {
      const user = await fetch("/auth/me", {
        headers: { Authorization: `Bearer ${token}` },
      })
        .then((response) => response.json())
        .catch(() => null);

      if (user.username) {
        setCurrentUser(user.username);
      }
    })();
  }, [token]);

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

    setToken(response.token);
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

    setToken(loginResponse.token);
    alert("Login successful");
  }

  return (
    <main>
      <h1>Passkeys Example</h1>
      {currentUser ? (
        <div>
          <p>Logged in as {currentUser}</p>
          <button onClick={() => setToken("")}>Logout</button>
        </div>
      ) : (
        <div>
          <h2>Register or Login</h2>
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
        </div>
      )}
    </main>
  );
}

export default App;
