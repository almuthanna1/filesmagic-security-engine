"use client";

import Link from "next/link";
import { logout } from "@/lib/api";
import styles from "@/app/page.module.css";

export default function LabNav() {
  return (
    <nav className={styles.nav} aria-label="Security Lab">
      <Link href="/">Scanner</Link>
      <Link href="/test-files">Test files</Link>
      <Link href="/evaluation">Malware evaluation</Link>
      <button type="button" className={styles.linkButton} onClick={() => logout().then(() => location.reload())}>
        Log out
      </button>
    </nav>
  );
}
