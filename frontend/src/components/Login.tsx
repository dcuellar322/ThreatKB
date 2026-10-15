import { useState } from "react";
import { Shield } from "lucide-react";
import { write } from "../lib/api";
export function Login({ onLogin, notify }: any) {
  const [email, setEmail] = useState(""),
    [password, setPassword] = useState(""),
    [busy, setBusy] = useState(false);
  return (
    <main className="login">
      <section className="login-form">
        <div className="login-brand">
          <Shield size={26} />
          <strong>ThreatKB</strong>
        </div>
        <h1>Sign in</h1>
        <form
          onSubmit={async (e) => {
            e.preventDefault();
            setBusy(true);
            try {
              const r = await write("/login", { email, password });
              onLogin(r.user);
            } catch (error: any) {
              notify(error.message, true);
            } finally {
              setBusy(false);
            }
          }}
        >
          <label>
            Email address
            <input
              aria-label="Email address"
              autoFocus
              required
              type="email"
              autoComplete="username"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
            />
          </label>
          <label>
            Password
            <input
              aria-label="Password"
              required
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </label>
          <button className="primary" disabled={busy}>
            {busy ? "Signing in…" : "Sign in"}
          </button>
        </form>
      </section>
    </main>
  );
}
