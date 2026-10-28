import Link from "next/link";
import styles from "@/app/page.module.css";

export default function LabNav() {
  return (
    <nav className={styles.nav} aria-label="Security Lab">
      <Link href="/">Scanner</Link>
      <Link href="/test-files">Test files</Link>
      <Link href="/evaluation">Malware evaluation</Link>
    </nav>
  );
}
