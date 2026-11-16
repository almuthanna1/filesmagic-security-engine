import styles from "./ScanResultView.module.css";

const FIELDS = [
  "network_verified",
  "net_interfaces_safe",
  "net_loopback_only",
  "net_fallback_tunnel_inert",
  "capabilities_dropped",
] as const;

export default function IsolationReport({
  isolation,
  required,
  missing,
}: {
  isolation: Record<string, boolean>;
  required?: boolean;
  missing?: string[];
}) {
  const inertTunnelVerified = isolation.network_verified === true &&
    isolation.net_interfaces_safe === true &&
    isolation.net_loopback_only === false &&
    isolation.net_fallback_tunnel_inert === true;
  const failed = (missing?.length ?? 0) > 0 || (required === true &&
    ["network_verified", "net_interfaces_safe", "capabilities_dropped"].some((key) => isolation[key] === false));

  return (
    <div className={styles.isolationReport}>
      <p className={failed ? styles.isolationFailure : styles.isolationSummary}>
        {required ? "Strict isolation required. " : "Strict isolation not required. "}
        {missing === undefined ? "Required-control status not reported." :
          failed ? `Required isolation verification failed${missing.length ? `; missing: ${missing.join(", ")}` : ""}.` :
            "No required controls missing."}
      </p>
      {inertTunnelVerified && (
        <p className={styles.isolationSummary}>
          Loopback only is false because an inert, down tunl0 interface is present. The worker verified this allowed alternative, safe interfaces, and no usable network route.
        </p>
      )}
      <ul className={styles.isolationList}>
        {FIELDS.map((field) => (
          <li key={field}>
            <code>{field}</code>: {field in isolation ? String(isolation[field]) : "not reported"}
            {missing?.includes(field) ? " — required control missing" : ""}
          </li>
        ))}
        <li><code>isolation_required</code>: {required === undefined ? "not reported" : String(required)}</li>
        <li><code>isolation_missing</code>: {missing === undefined ? "not reported" : missing.length ? missing.join(", ") : "[]"}</li>
      </ul>
      {Object.entries(isolation).filter(([key]) => !FIELDS.includes(key as typeof FIELDS[number])).length > 0 && (
        <p className={styles.mono}>
          Other controls: {Object.entries(isolation).filter(([key]) => !FIELDS.includes(key as typeof FIELDS[number]))
            .map(([key, value]) => `${key}=${value}`).join("; ")}
        </p>
      )}
    </div>
  );
}
