"use client";

import { useId, useState } from "react";
import { ApiError, login } from "@/lib/api";
import styles from "@/app/page.module.css";

// Shown when the Lab session is missing or expired. Scanning requires an admin login.
export default function LoginForm({ onLogin }: { onLogin: () => void }) {
  const inputId = useId();
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await login(password);
      setPassword("");
      onLogin();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Login failed.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit} className={`${styles.panel} ${styles.gap}`} aria-labelledby={`${inputId}-heading`}>
      <h2 id={`${inputId}-heading`} className={styles.panelHeading}>
        Administrator login required
      </h2>
      <label htmlFor={inputId} className={styles.fieldLabel}>
        Password
      </label>
      <div className={styles.actions}>
        <input
          id={inputId}
          type="password"
          autoComplete="current-password"
          className={styles.input}
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
        />
        <button type="submit" className={styles.button} disabled={busy || !password}>
          {busy ? "Logging in…" : "Log in"}
        </button>
      </div>
      {error && (
        <div className={styles.error} role="alert">
          {error}
        </div>
      )}
    </form>
  );
}
